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
const request = require('request');
const utils = require('../../utils');

const authenticate = utils.readExampleFile(
  './test/templates/api/000-authenticate.json'
);

const admin_login = authenticate.good_admin_login;

let valid_token;
let users_ids = [];

describe('WEB - 2 - Hidden attributes: ', function() {

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

  // CREATE A USERS WITH DESCRIPTION VISIBLE AND HIDDEN
  // eslint-disable-next-line no-undef
  before(function(done) {

    users_attributes = [
      {
        user: {
            username: "uservisible",
            email: "uservisible@test.com",
            password: "uservisible",
            description: "This should be seen",
            extra: {
              visible_attributes: ['username', 'description']
            }
        },
      },
      {
        user: {
            username: "userhidden",
            email: "userhidden@test.com",
            password: "userhidden",
            description: "This should not be seen",
            extra: {
              visible_attributes: ['username']
            }
        }
      }
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
        let user_body = JSON.parse(body);
        users_ids.push(user_body.user.id)
        if (i === (users_attributes.length -1)) {
          done();
        }
      });
    }
  });


  describe('1) When request to /idm/users/<user_id> with a user with description attribute visible', function() {

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
          email: 'uservisible@test.com',
          password: 'uservisible',
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
          url: config.host + '/idm/users/'+ users_ids[0],
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

    it('should show description', function(done) {
        const third_party = {
          url: config.host + '/idm/users/'+ users_ids[0],
          method: 'GET',
          headers: {
            cookie: session_headers,
          },
        };

        request(third_party, function(error, response) {
          should.not.exist(error);
          const dom = new JSDOM(response.body);
          let description = dom.window.document.querySelector("div[class='description']");
          should.exist(description);
          done();
        });
    });
  });

  describe('2) When request to /idm/users/<user_id> with a user with description attribute hidden', function() {

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
          email: 'userhidden@test.com',
          password: 'userhidden',
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
          url: config.host + '/idm/users/'+ users_ids[1],
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

    it('should show description', function(done) {
        const third_party = {
          url: config.host + '/idm/users/'+ users_ids[1],
          method: 'GET',
          headers: {
            cookie: session_headers,
          },
        };

        request(third_party, function(error, response) {
          should.not.exist(error);
          const dom = new JSDOM(response.body);
          let description = dom.window.document.querySelector("div[class='description']");
          should.not.exist(description);
          done();
        });
    });
  });

});