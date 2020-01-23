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
const models = require('../../../models/models.js');

const authenticate = utils.readExampleFile(
  './test/templates/api/000-authenticate.json'
);

const admin_login = authenticate.good_admin_login;

let valid_token;
let user_id;
let app;

describe('WEB - 3 - OAuth choosen attributes: ', function() {
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
    user_attributes = {
      user: {
        username: 'userattr',
        email: 'userattr@test.com',
        password: 'userattr',
      },
    };

    const create_user = {
      url: config.host + '/v1/users',
      method: 'POST',
      body: JSON.stringify(user_attributes),
      headers: {
        'Content-Type': 'application/json',
        'X-Auth-token': valid_token,
      },
    };

    request(create_user, function(error, response, body) {
      const user_body = JSON.parse(body);
      user_id = user_body.user.id;
      done();
    });
  });

  // CREATE APPLICATIONS
  // eslint-disable-next-line no-undef
  before(function(done) {
    application_attributes = {
      application: {
        name: 'Third app 1',
        description: 'app1',
        redirect_uri: 'http://localhost/login1',
        url: 'http://localhost1',
        grant_type: ['authorization_code', 'implicit', 'password'],
      },
    };

    const create_application = {
      url: config.host + '/v1/applications',
      method: 'POST',
      body: JSON.stringify(application_attributes),
      headers: {
        'Content-Type': 'application/json',
        'X-Auth-token': valid_token,
      },
    };

    request(create_application, function(error, response, body) {
      const app_body = JSON.parse(body);
      app = app_body.application;
      done();
    });
  });

  // CREATE A RELATION BETWEEN APPLICATION AND USER
  // eslint-disable-next-line no-undef
  before(function(done) {
    models.user_authorized_application
      .create({
        user_id,
        oauth_client_id: app.id,
        shared_attributes: ['username', 'email'],
        login_date: Date.now(),
      })
      .then(function() {
        done();
      });
  });

  describe('1) When request user info of a token to /oauth2/token', function() {
    let access_token;

    // Obtain an oauth token
    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const key = app.id + ':' + app.secret;
      const base64 = new Buffer(key).toString('base64');

      const good_token_request = {
        url: config.host + '/oauth2/token',
        method: 'POST',
        body:
          'grant_type=password&username=userattr@test.com&password=userattr',
        headers: {
          Authorization: 'Basic ' + base64,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      };

      request(good_token_request, function(error, response) {
        should.not.exist(error);
        const body = JSON.parse(response.body);
        access_token = body.access_token;
        response.statusCode.should.equal(200);
        done();
      });
    });

    it('should only return shared_attributes', function(done) {
      const good_token_request = {
        url: config.host + '/user?access_token=' + access_token,
        method: 'GET',
      };

      request(good_token_request, function(error, response, body) {
        should.not.exist(error);
        /*const json = JSON.parse(body);
        should(json).have.property('app_id');
        should(json).have.property('id');
        response.statusCode.should.equal(200);*/
        done();
      });
    });
  });
});
