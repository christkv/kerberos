'use strict';
const kerberos = require('..');
const MongoClient = require('mongodb').MongoClient;
const expect = require('chai').expect;
const os = require('os');
if (os.type() !== 'OS/390') {
  const SegfaultHandler = require('segfault-handler');
  SegfaultHandler.registerHandler();
}

const password = process.env.KERBEROS_PASSWORD;
const realm = process.env.KERBEROS_REALM;
const hostname = process.env.KERBEROS_HOSTNAME;
const username = `${process.env.KERBEROS_USERNAME}@${realm}`;
const service = `mongodb/${hostname}`;
const port = process.env.KERBEROS_PORT || '27017';
const upn = username;

function authenticate(options, callback) {
  const db = options.db;
  const krbClient = options.krbClient;
  const challenge = options.challenge || '';
  const start = options.start || false;
  const conversationId = options.conversationId;

  let promise;
  if (callback == null || typeof callback !== 'function') {
    promise = new Promise((resolve, reject) => {
      callback = function(err, res) {
        if (err) return reject(err);
        resolve(res);
      };
    });
  }

  if (start) {
    krbClient.step('', (err, payload) => {
      expect(err).to.not.exist;

      db.command({ saslStart: 1, mechanism: 'GSSAPI', payload }, (err, dbResponse) => {
        expect(err).to.not.exist;

        authenticate(
          {
            db,
            krbClient,
            challenge: dbResponse.payload,
            conversationId: dbResponse.conversationId
          },
          callback
        );
      });
    });

    return promise;
  }

  krbClient.step(challenge, (err, payload) => {
    payload = payload || '';

    db.command({ saslContinue: 1, conversationId, payload }, (err, dbResponse) => {
      if (krbClient.contextComplete) {
        callback(null, { challenge: dbResponse.payload, conversationId });
        return;
      }

      if (err) return callback(err, null);
      authenticate({ db, krbClient, conversationId, challenge: payload }, callback);
    });
  });

  return promise;
}

const test = {};
describe('Kerberos (win32)', function() {
  this.timeout(60000);
  before(function() {
    if (os.type() !== 'Windows_NT') this.skip();
  });

  beforeEach(function() {
    test.client = new MongoClient(`mongodb://${hostname}:${port}/`);
  });

  afterEach(function() {
    test.client.close().then(() => delete test.client);
  });

  it.skip('should create a kerberos client', function() {
    // this is a very basic test used to pass appveyor and provide prebuild binaries
    return kerberos.initializeClient(service, { user: username, password }).then(krbClient => {
      expect(krbClient).to.exist;
    });
  });

  it.skip('should work from windows', function(done) {
    test.client.connect((err, client) => {
      expect(err).to.not.exist;

      const db = client.db('$external');

      kerberos.initializeClient(service, { user: username, password }, (err, krbClient) => {
        expect(err).to.not.exist;

        authenticate({ db, krbClient, start: true }, (err, authResponse) => {
          expect(err).to.not.exist;

          krbClient.unwrap(authResponse.challenge, (err, unwrapped) => {
            expect(err).to.not.exist;

            // RFC-4752
            const challengeBytes = Buffer.from(unwrapped, 'base64');
            expect(challengeBytes).to.have.length(4);

            // Manually create an authorization message and encrypt it. This
            // is the "no security layer" message as detailed in RFC-4752,
            // section 3.1, final paragraph. This is also the message created
            // by calling authGSSClientWrap with the "user" option.
            // const UPN = Buffer.from(upn, 'utf8').toString('utf8');
            const msg = Buffer.from(`\x01\x00\x00\x00${upn}`).toString('base64');
            krbClient.wrap(msg, (err, custom) => {
              expect(err).to.not.exist;
              expect(custom).to.exist;

              // Wrap using unwrapped and user principal
              krbClient.wrap(unwrapped, { user: upn }, (err, wrapped) => {
                expect(err).to.not.exist;
                expect(wrapped).to.exist;

                db.command(
                  {
                    saslContinue: 1,
                    conversationId: authResponse.conversationId,
                    payload: wrapped
                  },
                  err => {
                    expect(err).to.not.exist;
                    expect(krbClient.username).to.exist;
                    done();
                  }
                );
              });
            });
          });
        });
      });
    });
  });

  it.skip('should work from windows using promises', function() {
    return test.client.connect().then(client => {
      const db = client.db('$external');

      return kerberos.initializeClient(service, { user: username, password }).then(krbClient => {
        return authenticate({ db, krbClient, start: true }).then(authResponse => {
          return krbClient.unwrap(authResponse.challenge).then(unwrapped => {
            // RFC-4752
            const challengeBytes = Buffer.from(unwrapped, 'base64');
            expect(challengeBytes).to.have.length(4);

            // Manually create an authorization message and encrypt it. This
            // is the "no security layer" message as detailed in RFC-4752,
            // section 3.1, final paragraph. This is also the message created
            // by calling authGSSClientWrap with the "user" option.
            // const UPN = Buffer.from(upn, 'utf8').toString('utf8');
            const msg = Buffer.from(`\x01\x00\x00\x00${upn}`).toString('base64');
            return krbClient
              .wrap(msg)
              .then(custom => {
                expect(custom).to.exist;

                // Wrap using unwrapped and user principal
                return krbClient.wrap(unwrapped, { user: upn });
              })
              .then(wrapped => {
                expect(wrapped).to.exist;
                return db.command({
                  saslContinue: 1,
                  conversationId: authResponse.conversationId,
                  payload: wrapped
                });
              })
              .then(() => {
                expect(krbClient.username).to.exist;
              });
          });
        });
      });
    });
  });
});
