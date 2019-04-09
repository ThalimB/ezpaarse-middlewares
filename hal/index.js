'use strict';

const co = require('co');
const cache = ezpaarse.lib('cache')('hal');
let methal;

/**
 * Workaround to prevent processes to fail because this middleware is included by default
 * but the methal module has been renamed
 */
try {
  // eslint-disable-next-line global-require
  methal = require('@ezpaarse-project/methal');
} catch (e) {
  methal = null;
}

/**
* Enrich ECs with hal data
*/
module.exports = function () {
  const self         = this;
  const report       = this.report;
  const req          = this.request;
  const activated    = (methal !== null) && /^true$/i.test(req.header('hal-enrich'));
  const cacheEnabled = !/^false$/i.test(req.header('hal-cache'));

  if (!activated) { return function (ec, next) { next(); }; }

  self.logger.verbose('hal cache: %s', cacheEnabled ? 'enabled' : 'disabled');

  const ttl         = parseInt(req.header('hal-ttl')) || 3600 * 24 * 7;
  const throttle    = parseInt(req.header('hal-throttle')) || 100;
  const packetSize  = parseInt(req.header('hal-paquet-size')) || 150;
  const maxAttempts = 5;
  // Minimum number of ECs to keep before resolving them
  let bufferSize    = parseInt(req.header('hal-buffer-size'));

  if (isNaN(bufferSize)) {
    bufferSize = 1000;
  }

  const buffer = [];
  let busy = false;
  let finalCallback = null;

  if (!cache) {
    const err = new Error('failed to connect to mongodb, cache not available for hal');
    err.status = 500;
    return err;
  }

  report.set('general', 'hal-queries', 0);
  report.set('general', 'site-queries', 0);
  report.set('general', 'same-queries', 0);
  report.set('general', 'hal-fails', 0);

  return new Promise(function (resolve, reject) {
    cache.checkIndexes(ttl, function (err) {
      if (err) {
        self.logger.error(`hal: failed to ensure indexes : ${err.message}`);
        return reject(new Error('failed to ensure indexes for the cache of hal'));
      }

      resolve(process);
    });
  });

  /**
  * enrich ec with cache or api hal
  * @param  {object} ec the EC to process, null if no EC left
  * @param  {Function} next the function to call when we are done with the given EC
  */
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

  function getPacket() {
    const packet = {
      'ecs': [],
      'identifiants': new Set(),
      'docids': new Set()
    };

    return co(function* () {

      while (packet.identifiants.size + packet.docids.size < packetSize) {
        const [ec, done] = buffer.shift() || [];
        if (!ec) { break; }

        // Reformatage de la date pour le chargement dans SolR
        ec.datetime = ec.datetime.replace('+01:00', 'Z');

        // Ajout d'un paramètre booléen pour différencier les redirections
        ec['hal_redirection'] = (ec.status == 301 || ec.status == 302 || ec.status == 304);

        // Formatage pour des problèmes de comparaisons string / int
        if (ec.hal_docid) {
          ec['hal_docid'] = ec.hal_docid.toString();
        }

        // Formatage de la collection
        if (ec.hal_consult_collection) {
          ec['hal_consult_collection'] = ec.hal_consult_collection.toUpperCase();
        }

        // Formatage de la taille
        if (!ec.size) {
          ec.size = 0;
        }

        ec['hal_fulltext'] = (ec.mime === 'PDF');

        if (ec.platform !== 'hal') {
          done();
          continue;
        }

        let cachedDocument = yield checkCache(ec.hal_identifiant || ec.hal_docid);

        if (cachedDocument && cachedDocument.hal_docid) {
          // récupération des données en cache. Attention, elle doivent bien
          // s'appeler quand elles sont mises en cache pour aller direct en sortie
          for (let prop in cachedDocument) {
            ec[prop] = cachedDocument[prop];
          }

          const redirected = yield addSiteData(ec, cachedDocument.hal_sid);

          if (redirected) {
            const err = new Error('portal to portal redirection');
            err.type = 'EIRRELEVANT';
            done(err);
            continue;
          }

          done();
          continue;
        }

        packet.ecs.push([ec, done]);

        if (ec.hal_identifiant) {
          // On crée un paquet d'identifiants
          packet.identifiants.add(ec.hal_identifiant);
        } else if (ec.hal_docid) {
          // On crée un paquet de docids
          packet.docids.add(ec.hal_docid);
        }
      }

      return packet;
    });
  }

  function checkCache(identifier) {
    return new Promise((resolve, reject) => {
      if (!identifier) { return resolve(); }

      cache.get(identifier, (err, cachedDocid) => {
        if (err) { return reject(err); }
        resolve(cachedDocid);
      });
    });
  }

  function drainBuffer(callback) {
    return co(function* () {

      while (buffer.length >= bufferSize || (finalCallback && buffer.length > 0)) {

        const packet = yield getPacket();

        if (packet.ecs.length === 0 || packet.identifiants.size + packet.docids.size === 0) {
          self.logger.silly('hal: no IDs in the paquet');
          yield new Promise(resolve => { setImmediate(resolve); });
          continue;
        }

        const results = new Map();
        let tries = 0;
        let docs;

        while (!docs) {
          if (++tries > maxAttempts) {
            const err = new Error(`Failed to query HAL ${maxAttempts} times in a row`);
            return Promise.reject(err);
          }

          try {
            docs = yield queryHal(Array.from(packet.identifiants), Array.from(packet.docids));
          } catch (e) {
            self.logger.error(`hal: ${e.message}`);
          }

          yield wait();
        }

        for (const doc of docs) {

          if (!doc.halId_s || !doc.docid) { continue; }

          if (results.has(doc.halId_s)) {
            // Dans le cas où on a plusieurs fois le même identifiant avec des docids différents
            // On merge les données

            let currentDoc = results.get(doc.halId_s);

            if (doc.status_i == 11) {
              // On privilégie le docid du document en ligne (dernière version)
              currentDoc.docid = doc.docid;
              currentDoc['sid_i'] = doc.sid_i;
            }

            // On merge les tampons de toutes les versions du même document
            currentDoc['collId_i'] = (currentDoc.collId_i || []).concat(doc.collId_i || []);

            continue;
          }

          results.set(doc.docid.toString(), doc);
          results.set(doc.halId_s.toString(), doc);
        }

        for (let [ec, done] of packet.ecs) {
          if (!ec.hal_identifiant && !ec.hal_docid) {
            done();
            continue;
          }

          let relatedDoc = null;

          if (results.has(ec.hal_identifiant) || results.has(ec.hal_docid)) {
            relatedDoc = results.get(ec.hal_identifiant) || results.get(ec.hal_docid);

          } else if (ec.hal_identifiant) {
            // Dans le cas où on ne trouve pas l'identifiant dans l'index,
            // on cherche une correspondance avec un identifiant fusionné

            try {
              relatedDoc = yield querySameHal(ec.hal_identifiant);
            } catch (e) {
              relatedDoc = null;
            }
          }

          /**
           * Dans le cas où on ne trouve pas le docid dans l'index, on ne sait pas à quel
           * nouvel identifiant il peut être rattaché... c'est perdu !!
           * Mais on le garde quand même dans la sortie
           */

          try {
            ec = yield loadEC(ec, relatedDoc);
          } catch (e) {
            self.logger.error('docid null non chargé');
            return Promise.reject(e);
          }

          if (!ec) {
            // Il faut virer l'EC car c'est une redirection de portail à portail.
            done(new Error());
            continue;
          }

          done();
        }
      }
    });
  }

  /**
   * Merge a HAL document into an EC and cache it
   * @param {Object} ec the EC that should be enriched
   * @param {Object} doc the HAL document to merge into the EC
   */
  function loadEC(ec, doc) {
    return co(function* () {

      // On conserve l'identifiant originel (avant fusion par exemple !) pour le cacher
      let identifiantOriginel = ec.hal_identifiant;
      let cacheDoc = null;
      let sidDepot = null;

      if (doc) {
        ec['hal_docid']         = doc.docid;
        ec['hal_identifiant']   = doc.halId_s;
        ec['publication_title'] = (doc.title_s || [''])[0];
        ec['hal_tampons']       = (doc.collId_i || []).join(',');
        ec['hal_tampons_name']  = (doc.collCode_s || []).join(',');
        ec['hal_domains']       = (doc.domain_s || []).join(',');

        sidDepot = doc.sid_i;

        // Formatage du document à mettre en cache
        cacheDoc = [];
        cacheDoc['hal_docid']         = ec.hal_docid;
        cacheDoc['hal_identifiant']   = ec.hal_identifiant;
        cacheDoc['publication_title'] = ec.publication_title;
        cacheDoc['hal_tampons']       = ec.hal_tampons;
        cacheDoc['hal_tampons_name']  = ec.hal_tampons_name;
        cacheDoc['hal_domains']       = ec.hal_domains;
        cacheDoc['hal_sid']           = sidDepot;
      }

      let idTocache = identifiantOriginel || ec.hal_identifiant;

      if (idTocache) {
        try {
          yield cacheResult(idTocache, cacheDoc);
        } catch (e) {
          report.inc('general', 'hal-cache-fail');
        }
      }

      if (ec.hal_docid) {
        try {
          yield cacheResult(ec.hal_docid, cacheDoc);
        } catch (e) {
          report.inc('general', 'hal-cache-fail');
        }
      }

      const redirected = yield addSiteData(ec, sidDepot);

      return redirected ? null : ec;
    });
  }

  function wait() {
    return new Promise(resolve => { setTimeout(resolve, throttle); });
  }

  /**
   * Add site data to the EC
   * @param {Object} ec the EC to enrich
   * @param {String} sidDepot the site ID
   * @return {Boolean} redirected wether the EC is a redirection or not
   */
  function addSiteData(ec, sidDepot) {
    return co(function* () {
      if (!sidDepot) { return false; }

      const sidDomain = yield getSite('PORTAIL', ec.domain, 'docid');

      if (ec.hal_consult_collection) {
        // eslint-disable-next-line max-len
        ec['hal_consult_collection_sid'] = yield getSite('COLLECTION', ec.hal_consult_collection, 'docid');
      }

      if (ec.hal_redirection === true) {
        ec['hal_endpoint_portail_sid'] = sidDepot;
        ec['hal_endpoint_portail'] = yield getSite('ID', sidDepot, 'url_s');
      }

      if (ec.hal_redirection === true && !ec.hal_consult_collection && sidDomain == sidDepot) {
        return true;
      }

      if (ec.hal_redirection === true) {
        ec['hal_redirect_portail_sid'] = sidDomain;
        ec['hal_redirect_portail'] = ec.domain;
      } else {
        ec['hal_endpoint_portail_sid'] = sidDomain;
        ec['hal_endpoint_portail'] = ec.domain;
      }

      return false;
    });
  }

  function queryHal(identifiants, docids) {
    report.inc('general', 'hal-queries');

    let search = `halId_s:(${identifiants.map(id => `${id}`).join(' OR ')})`;

    if (docids.length > 0) {
      search += ` OR docid:(${docids.map(id => `${id}`).join(' OR ')})`;
    }

    return new Promise((resolve, reject) => {
      /**
       * Attention, un identifiant peut avoir plusieurs docids.
       * On ne peut donc pas définir rows à packetSize. Pour viser large, on multiple par 2.
       * Si jamais on a plus de 2 versions de chaque document, c'est la limite.
       * Mais il est peu probable que ça arrive.
       */
      const opts = {
        fields: 'docid,halId_s,title_s,collId_i,collCode_s,domain_s,sid_i,status_i',
        rows: packetSize * 2,
        core: 'hal'
      };

      methal.find(search, opts, (err, docs) => {
        if (err) {
          report.inc('general', 'hal-fails');
          return reject(err);
        }

        if (!Array.isArray(docs)) {
          report.inc('general', 'hal-fails');
          return reject(new Error('invalid response'));
        }

        return resolve(docs);
      });
    });
  }

  function querySameHal(identifiant) {
    report.inc('general', 'same-queries');

    let search = `halIdSameAs_s:${identifiant}`;

    return new Promise((resolve, reject) => {
      const opts = {
        core: 'hal',
        fields: 'docid,halId_s,title_s,collId_i,collCode_s,domain_s,sid_i,status_i'
      };

      methal.findOne(search, opts, (err, doc) => {
        if (err) {
          report.inc('general', 'hal-fails');
          return reject(err);
        }

        return resolve(doc);
      });
    });
  }

  function querySiteHal(type, site, returnParam) {
    report.inc('general', 'site-queries');

    let search;

    if (type == 'ID') {
      search = `docid:${site}`;
    } else if (type == 'COLLECTION') {
      search = `site_s:${site}`;
    } else {
      search = `url_s:${site}`;
    }

    return new Promise((resolve, reject) => {
      methal.findOne(search, { fields: returnParam, core: 'ref_site' }, (err, doc) => {
        if (err) {
          report.inc('general', 'hal-fails');
          return reject(err);
        }

        return resolve(doc);
      });
    });
  }

  function getSite(type, sitename, returnParam) {
    return co(function* () {

      // Récupération du sid ou nom dans le cache si possible
      let cachedParam = yield checkCache(sitename);
      if (cachedParam) {
        return cachedParam;
      }

      let toreturn;
      let tries = 0;

      // Récupération du sid depuis l'API de HAL
      while (!toreturn) {
        if (++tries > maxAttempts) {
          throw new Error(`Failed to query ref_site HAL ${maxAttempts} times in a row`);
        }

        try {
          let doc = yield querySiteHal(type, sitename, returnParam);
          if (!doc) {
            self.logger.error(`No site found for sitename ${sitename}`);
            toreturn = 0;
            break;
          } else {
            toreturn = doc[returnParam];
          }
        } catch (e) {
          // La requête à l'API a planté mais on essaie maxAttempts fois avant de déclarer forfait
          self.logger.error(`Query ref_site Hal failed : ${e.message} for sitename : ${sitename}`);
        }

        yield wait();
      }


      try {
        // On cache à la fois la correspondance ID=>Name et Name=>ID
        if (Array.isArray(toreturn)) {
          toreturn = toreturn[0];
        }

        yield cacheResult(sitename, toreturn);
        yield cacheResult(toreturn, sitename);
      } catch (e) {
        report.inc('general', 'hal-cache-fail');
      }

      return toreturn;
    });
  }

  function cacheResult(id, doc) {

    return new Promise((resolve, reject) => {
      if (!id || !doc) { return resolve(); }

      cache.set(id, doc, (err, result) => {
        if (err) { return reject(err); }
        resolve(result);
      });
    });
  }

};
