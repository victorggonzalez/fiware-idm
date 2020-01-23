/*
 * Copyright 2019 -  Universidad Politécnica de Madrid.
 *
 * This file is part of Keyrock
 *
 */

// Load database configuration before
require('../../config/config_database');

// Dom parser
const jsdom = require('jsdom');

// eslint-disable-next-line snakecase/snakecase
const { JSDOM } = jsdom;

// const keyrock = require('../../bin/www');
const config = require('../../../config.js');
const should = require('should');
const assert = require('chai').assert;
const request = require('request');
const utils = require('../../utils');
const models = require('../../../models/models.js');

const authenticate = utils.readExampleFile(
  './test/templates/api/000-authenticate.json'
);

const admin_login = authenticate.good_admin_login;

let valid_token;
const users_ids = [];
const app_ids = [];

describe('WEB - 1 - Third party applications page: ', function() {
  // Increase timeout in this case beacause it has been made operations directly with the database
  this.timeout(7000);

  // CREATE A VALID ADMIN TOKEN
  // eslint-disable-next-line no-undef
  before(function(done) {
    const good_admin_login = {
      url: config.host + '/v1/auth/tokens',
      method: 'POST',
      json: admin_login,
      headers: {
        'Content-Type': 'application/json',
      },
    };
    return request(good_admin_login, function(error, response) {
      valid_token = response.headers['x-subject-token'];
      done();
    });
  });

  // CREATE A USER
  // eslint-disable-next-line no-undef
  before(function(done) {
    users_attributes = [
      {
        user: {
          username: 'user_3rd_party',
          email: 'user_3rd_party@test.com',
          password: 'user_3rd_party',
        },
      },
      {
        user: {
          username: 'user_not_3rd_party',
          email: 'user_not_3rd_party@test.com',
          password: 'user_not_3rd_party',
        },
      },
    ];

    for (let i = 0; i < users_attributes.length; i++) {
      const create_user = {
        url: config.host + '/v1/users',
        method: 'POST',
        body: JSON.stringify(users_attributes[i]),
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-token': valid_token,
        },
      };

      request(create_user, function(error, response, body) {
        const user_body = JSON.parse(body);
        users_ids.push(user_body.user.id);
        if (i === users_attributes.length - 1) {
          done();
        }
      });
    }
  });

  // CREATE APPLICATIONS
  // eslint-disable-next-line no-undef
  before(function(done) {
    applications_attributes = [
      {
        application: {
          name: 'Third app 1',
          description: 'app1',
          redirect_uri: 'http://localhost/login1',
          url: 'http://localhost1',
          grant_type: ['authorization_code', 'implicit', 'password'],
        },
      },
      {
        application: {
          name: 'Third app 2',
          description: 'app2',
          redirect_uri: 'http://localhost/login2',
          url: 'http://localhost2',
          grant_type: ['authorization_code', 'implicit', 'password'],
        },
      },
    ];

    for (let i = 0; i < applications_attributes.length; i++) {
      const create_application = {
        url: config.host + '/v1/applications',
        method: 'POST',
        body: JSON.stringify(applications_attributes[i]),
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-token': valid_token,
        },
      };

      request(create_application, function(error, response, body) {
        const app_body = JSON.parse(body);
        app_ids.push(app_body.application.id);
        if (i === applications_attributes.length - 1) {
          done();
        }
      });
    }
  });

  // CREATE A RELATION BETWEEN APPLICATIONS AND USER
  // eslint-disable-next-line no-undef
  before(function(done) {
    for (let i = 0; i < app_ids.length; i++) {
      models.user_authorized_application
        .create({
          user_id: users_ids[0],
          oauth_client_id: app_ids[i],
          shared_attributes: ['username', 'email'],
          login_date: Date.now(),
        })
        .then(function() {
          if (i === app_ids.length - 1) {
            done();
          }
        });
    }
  });

  describe('1) When request to /idm/users/<user_id>/_third_party_applications with a user with authorized apps', function() {
    let csrf_token;
    let csrf_headers;
    let session_headers;

    // Obtain csrf token from web page
    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const obtain_csrf_token = {
        url: config.host + '/auth/login',
        method: 'GET',
      };

      request(obtain_csrf_token, function(error, response) {
        should.not.exist(error);
        const dom = new JSDOM(response.body);
        csrf_token = dom.window.document.querySelector("input[name='_csrf']")
          .value;
        csrf_headers = response.headers['set-cookie'];
        done();
      });
    });

    // Authenticate user
    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const auth_page = {
        url: config.host + '/auth/login',
        method: 'POST',
        json: {
          _csrf: csrf_token,
          email: 'user_3rd_party@test.com',
          password: 'user_3rd_party',
        },
        headers: {
          'Content-Type': 'application/json',
          cookie: csrf_headers,
        },
      };

      request(auth_page, function(error, response) {
        should.not.exist(error);
        session_headers = response.headers['set-cookie'];
        done();
      });
    });

    it('should return a 200 Ok', function(done) {
      const third_party = {
        url:
          config.host +
          '/idm/users/' +
          users_ids[0] +
          '/_third_party_applications',
        method: 'GET',
        headers: {
          cookie: session_headers,
        },
      };

      request(third_party, function(error, response) {
        should.not.exist(error);
        response.statusCode.should.equal(200);
        done();
      });
    });

    it('should show 2 panels', function(done) {
      const third_party = {
        url:
          config.host +
          '/idm/users/' +
          users_ids[0] +
          '/_third_party_applications',
        method: 'GET',
        headers: {
          cookie: session_headers,
        },
      };

      request(third_party, function(error, response) {
        should.not.exist(error);
        const dom = new JSDOM(response.body);
        panels = dom.window.document.querySelectorAll(
          "div[class='panel panel-default info']"
        );
        assert.strictEqual(
          panels.length,
          2,
          'There should be rendered two panels'
        );
        done();
      });
    });
  });

  describe('2) When request to /idm/users/<user_id>/_third_party_applications with a user without authorized apps', function() {
    let csrf_token;
    let csrf_headers;
    let session_headers;

    // Obtain csrf token from web page
    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const obtain_csrf_token = {
        url: config.host + '/auth/login',
        method: 'GET',
      };

      request(obtain_csrf_token, function(error, response) {
        should.not.exist(error);
        const dom = new JSDOM(response.body);
        csrf_token = dom.window.document.querySelector("input[name='_csrf']")
          .value;
        csrf_headers = response.headers['set-cookie'];
        done();
      });
    });

    // Authenticate user
    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const auth_page = {
        url: config.host + '/auth/login',
        method: 'POST',
        json: {
          _csrf: csrf_token,
          email: 'user_not_3rd_party@test.com',
          password: 'user_not_3rd_party',
        },
        headers: {
          'Content-Type': 'application/json',
          cookie: csrf_headers,
        },
      };

      request(auth_page, function(error, response) {
        should.not.exist(error);
        session_headers = response.headers['set-cookie'];
        done();
      });
    });

    it('should return a 200 Ok', function(done) {
      const third_party = {
        url:
          config.host +
          '/idm/users/' +
          users_ids[1] +
          '/_third_party_applications',
        method: 'GET',
        headers: {
          cookie: session_headers,
        },
      };

      request(third_party, function(error, response) {
        should.not.exist(error);
        response.statusCode.should.equal(200);
        done();
      });
    });

    it('should not show any panel', function(done) {
      const third_party = {
        url:
          config.host +
          '/idm/users/' +
          users_ids[1] +
          '/_third_party_applications',
        method: 'GET',
        headers: {
          cookie: session_headers,
        },
      };

      request(third_party, function(error, response) {
        should.not.exist(error);
        const dom = new JSDOM(response.body);
        panels = dom.window.document.querySelector("div[id='card-container']");
        paragraph = panels.querySelector('p');
        paragraph.nodeName.should.equal('P');
        done();
      });
    });
  });

  describe('3) When delete an authorized application', function() {
    let csrf_token;
    let csrf_headers;
    let session_headers;

    // Obtain csrf token from web page
    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const obtain_csrf_token = {
        url: config.host + '/auth/login',
        method: 'GET',
      };

      request(obtain_csrf_token, function(error, response) {
        should.not.exist(error);
        const dom = new JSDOM(response.body);
        csrf_token = dom.window.document.querySelector("input[name='_csrf']")
          .value;
        csrf_headers = response.headers['set-cookie'];
        done();
      });
    });

    // Authenticate user
    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const auth_page = {
        url: config.host + '/auth/login',
        method: 'POST',
        json: {
          _csrf: csrf_token,
          email: 'user_3rd_party@test.com',
          password: 'user_3rd_party',
        },
        headers: {
          'Content-Type': 'application/json',
          cookie: csrf_headers,
        },
      };

      request(auth_page, function(error, response) {
        should.not.exist(error);
        session_headers = response.headers['set-cookie'];
        done();
      });
    });

    // Authenticate user
    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const third_party = {
        url:
          config.host +
          '/idm/users/' +
          users_ids[0] +
          '/_third_party_applications',
        method: 'GET',
        headers: {
          cookie: session_headers,
        },
      };

      request(third_party, function(error, response) {
        const dom = new JSDOM(response.body);
        csrf_token = dom.window.document.querySelector("input[name='_csrf']")
          .value;

        csrf_headers = response.headers['set-cookie'];
        done();
      });
    });

    it('should return a 200 Ok and only show one panel', function(done) {
      session_headers.push(csrf_headers[0]);
      const delete_third_party = {
        url:
          config.host +
          '/idm/users/' +
          users_ids[0] +
          '/_third_party_applications',
        method: 'DELETE',
        json: {
          _csrf: csrf_token,
          app_id: app_ids[0],
        },
        headers: {
          cookie: session_headers,
        },
      };

      request(delete_third_party, function(error, response) {
        should.not.exist(error);
        response.statusCode.should.equal(200);

        const dom = new JSDOM(response.body);
        panels = dom.window.document.querySelectorAll(
          "div[class='panel panel-default info']"
        );
        assert.strictEqual(
          panels.length,
          1,
          'There should be rendered one panel'
        );
        done();
      });
    });
  });
});
