'use strict';

const co         = require('co');
const crossref   = require('crossref');
const cache      = ezpaarse.lib('cache')('crossref');
const doiPattern = /^10\.[0-9]{4,}\/[a-z0-9\-._: ;()/]+$/i;

/**
 * Enrich ECs with crossref data
 */
module.exports = function () {
  const self         = this;
  const req          = this.request;
  const report       = this.report;
  const disabled     = /^false$/i.test(req.header('crossref-enrich'));
  const cacheEnabled = !/^false$/i.test(req.header('crossref-cache'));

  if (disabled) {
    self.logger.verbose('Crossref enrichment not activated');
    return function (ec, next) { next(); };
  }

  self.logger.verbose('Crossref cache: %s', cacheEnabled ? 'enabled' : 'disabled');

  if (this.job.outputFields.added.indexOf('type') === -1) {
    this.job.outputFields.added.push('type');
  }
  if (this.job.outputFields.added.indexOf('subject') === -1) {
    this.job.outputFields.added.push('subject');
  }

  const ttl        = parseInt(req.header('crossref-ttl')) || 3600 * 24 * 7;
  let throttle     = parseInt(req.header('crossref-throttle')) || 200;
  // Maximum number of DOIs to query in a single request
  const packetSize = parseInt(req.header('crossref-paquet-size')) || 50;
  // Minimum number of ECs to keep before resolving them
  let bufferSize   = parseInt(req.header('crossref-buffer-size'));

  if (isNaN(bufferSize)) {
    bufferSize = 1000;
  }

  const buffer = [];
  let busy = false;
  let finalCallback = null;

  self.logger.verbose('Crossref enrichment activated');
  self.logger.verbose('Crossref throttle: %dms', throttle);
  self.logger.verbose('Crossref paquet size: %d', packetSize);
  self.logger.verbose('Crossref buffer size: %d', bufferSize);

  report.set('general', 'crossref-queries', 0);
  report.set('general', 'crossref-fails', 0);
  report.set('general', 'crossref-invalid-dois', 0);

  return new Promise(function (resolve, reject) {
    cache.checkIndexes(ttl, function (err) {
      if (err) {
        self.logger.error('Crossref: failed to ensure indexes');
        return reject(new Error('failed to ensure indexes for the cache of Crossref'));
      }

      resolve(process);
    });
  });

  function process(ec, next) {
    if (!ec) {
      finalCallback = next;
      if (!busy) {
        drainBuffer().then(() => {
          finalCallback();
        }).catch(err => {
          this.job._stop(err);
        });
      }
      return;
    }

    buffer.push([ec, next]);

    if (buffer.length > bufferSize && !busy) {
      busy = true;
      self.saturate();

      drainBuffer().then(() => {
        busy = false;
        self.drain();

        if (finalCallback) { finalCallback(); }
      }).catch(err => {
        this.job._stop(err);
      });
    }
  }

  /**
   * Iterate over the buffer, remove ECs with no DOI/PII or cached DOI/PII
   * return a packet of ecs with an uncached DOI
   */
  function getPacket() {
    const packet = {
      'ecs': [],
      'doi': new Set(),
      'alternative-id': new Set()
    };

    return co(function* () {

      while (packet.doi.size < packetSize && packet['alternative-id'].size < packetSize) {
        const [ec, done] = buffer.shift() || [];
        if (!ec) { return packet; }

        if (!ec.pii && !ec.doi) {
          done();
          continue;
        }

        if (ec.pii && cacheEnabled) {
          const cachedDoc = yield checkCache(ec.pii);

          if (cachedDoc) {
            aggregate(cachedDoc, ec);
            done();
            continue;
          }
        }

        if (ec.doi && cacheEnabled) {
          if (!doiPattern.test(ec.doi)) {
            report.inc('general', 'crossref-invalid-dois');
            done();
            continue;
          }

          const cachedDoc = yield checkCache(ec.doi);

          if (cachedDoc) {
            aggregate(cachedDoc, ec);
            done();
            continue;
          }
        }

        packet.ecs.push([ec, done]);
        if (ec.doi) { packet.doi.add(ec.doi); }
        if (ec.pii) { packet['alternative-id'].add(ec.pii); }
      }

      return packet;
    });
  }

  function checkCache(identifier) {
    return new Promise((resolve, reject) => {
      if (!identifier) { return resolve(); }

      cache.get(identifier.toLowerCase(), (err, cachedDoc) => {
        if (err) { return reject(err); }
        resolve(cachedDoc);
      });
    });
  }

  function drainBuffer() {
    return co(function* () {

      while (buffer.length >= bufferSize || (finalCallback && buffer.length > 0)) {

        const packet = yield getPacket();

        if (packet.ecs.length === 0 || (packet.doi.size + packet['alternative-id'].size === 0)) {
          self.logger.silly('Crossref: no doi or pii in the paquet');
          yield new Promise(resolve => { setImmediate(resolve); });
          continue;
        }

        const maxAttempts = 5;
        const results     = new Map();

        for (const identifier of ['doi', 'alternative-id']) {
          if (packet[identifier].size === 0) { continue; }
          let tries = 0;
          let list;

          while (!list) {
            if (++tries > maxAttempts) {
              const err = new Error(`Failed to query Crossref ${maxAttempts} times in a row`);
              return Promise.reject(err);
            }

            try {
              list = yield queryCrossref(identifier, Array.from(packet[identifier]));
            } catch (e) {
              self.logger.error('Crossref: ', e.message);
              handleCrossrefError(e);
            }

            yield wait();
          }

          for (const item of list) {
            let { 'DOI': doi, 'alternative-id': pii } = item;

            if (doi) {
              doi = doi.toLowerCase();
              results.set(doi, item);

              try {
                yield cacheResult(doi, item);
              } catch (e) {
                report.inc('general', 'crossref-cache-fail');
              }
            }

            if (pii && pii[0]) {
              pii = pii[0].toLowerCase();
              results.set(pii, item);

              try {
                yield cacheResult(pii, item);
              } catch (e) {
                report.inc('general', 'crossref-cache-fail');
              }
            }
          }
        }

        for (const [ec, done] of packet.ecs) {
          if (ec.pii) {
            const pii = ec.pii.toLowerCase();

            if (results.has(pii)) {
              aggregate(results.get(pii), ec);
            } else {
              try {
                yield cacheResult(pii, {});
              } catch (e) {
                report.inc('general', 'crossref-cache-fail');
              }
            }
          }

          if (ec.doi) {
            const doi = ec.doi.toLowerCase();

            if (results.has(doi)) {
              aggregate(results.get(doi), ec);
            } else {
              try {
                yield cacheResult(doi, {});
              } catch (e) {
                report.inc('general', 'crossref-cache-fail');
              }
            }
          }

          done();
        }
      }
    });
  }

  function wait() {
    return new Promise(resolve => { setTimeout(resolve, throttle); });
  }

  function handleCrossrefError(e) {
    const match = /rate limit exceeded: (\d+) requests in (\d+)([smh])/i.exec(e.message);
    if (!match) { return; }

    let interval   = parseInt(match[2]);
    let nbRequests = parseInt(match[1]);

    if (interval > 0 && nbRequests > 0) {
      switch (match[3]) {
      case 'h':
        interval *= 60;
        // fallthrough
      case 'm':
        interval *= 60;
        // fallthrough
      case 's':
        interval *= 1000;
        throttle = nbRequests / interval;
        self.logger.verbose('Crossref: limiting queries to %d req in %d ms', nbRequests, interval);
      }
    }
  }

  function queryCrossref(property, values) {
    report.inc('general', 'crossref-queries');

    return new Promise((resolve, reject) => {
      crossref.works({ filter: { [property]: values }, rows: packetSize }, function (err, list) {
        if (err) {
          report.inc('general', 'crossref-fails');
          return reject(err);
        }

        if (!Array.isArray(list)) {
          report.inc('general', 'crossref-fails');
          return reject(new Error('invalid response'));
        }

        return resolve(list);
      });
    });
  }

  function cacheResult(id, item) {
    return new Promise((resolve, reject) => {
      if (!id || !item) { return resolve(); }

      cache.set(id, item, (err, result) => {
        if (err) { return reject(err); }
        resolve(result);
      });
    });
  }

  function aggregate(item, ec) {
    if (item['type'] && /([a-z]+)-([a-z]+)/.test(item['type'])) {
      ec['publication_title'] = ec['publication_title'] || item['container-title'];
    } else {
      ec['publication_title'] = ec['publication_title'] || item['title'];
    }
    if (item['issued'] && item['issued']['date-parts'] && item['issued']['date-parts'][0]) {
      ec['publication_date'] = ec['publication_date'] || item['issued']['date-parts'][0][0];
    }
    if (item['subject'] && Array.isArray(item['subject'])) {
      ec['subject'] = item['subject'].join(', ');
    }
    ec['doi'] = ec['doi'] || item['DOI'];
    ec['publisher_name'] = ec['publisher_name'] || item['publisher'];
    ec['type'] = item['type'];

    if (item['ISSN']) {
      const identifier = /([0-9A-Z-]*),([0-9-]+)/.exec(item['ISSN']);
      if (identifier && identifier[1]) {
        ec['print_identifier'] = ec['print_identifier'] || identifier[1];
        if (identifier[2]) {
          ec['online_identifier'] = ec['online_identifier'] || identifier[2]  ;
        }
      } else {
        ec['print_identifier'] = ec['print_identifier'] || item['ISSN'];
      }
    }
    return item;
  }
};
