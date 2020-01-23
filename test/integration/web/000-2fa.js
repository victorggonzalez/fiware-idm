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
let user_id;

describe('WEB - 0 - 2 factor authentication: ', function() {
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

  // CREATE A USER WITHOUT 2FA
  // eslint-disable-next-line no-undef
  before(function(done) {
    user_attributes = {
      user: {
        username: 'user_no_2fa',
        email: 'user_no_2fa@test.com',
        password: 'userno2fa',
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
      done();
    });
  });

  // CREATE A USER WITH 2FA ENABLE
  // eslint-disable-next-line no-undef
  before(function(done) {
    user_attributes = {
      user: {
        username: 'user2fa',
        email: 'user_2fa@test.com',
        password: 'user2fa',
        extra: {
          tfa: {
            answer: 'aaaa',
            secret: 'KRRUW6TNM5DWEJS5GMXSKMZ6LA2TA5CBLMRXW23ZJVXSUXREFFIA',
            enabled: true,
            question: 'aaaa',
          },
        },
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

  describe('1) When authenticate a user (without 2fa enable) through /auth/login', function() {
    let csrf_token;
    let csrf_headers;

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

    it('should return a 302 redirect to /idm', function(done) {
      const auth_page = {
        url: config.host + '/auth/login',
        method: 'POST',
        json: {
          _csrf: csrf_token,
          email: 'user_no_2fa@test.com',
          password: 'userno2fa',
        },
        headers: {
          'Content-Type': 'application/json',
          cookie: csrf_headers,
        },
      };

      request(auth_page, function(error, response) {
        should.not.exist(error);
        response.statusCode.should.equal(302);
        response.headers.location.should.equal('/idm');
        done();
      });
    });
  });

  describe('2) When authenticate a user (with 2fa enable) through /auth/login', function() {
    let csrf_token;
    let csrf_headers;

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

    it('should return a 200 and render new view ', function(done) {
      const auth_page = {
        url: config.host + '/auth/login',
        method: 'POST',
        json: {
          _csrf: csrf_token,
          email: 'user_2fa@test.com',
          password: 'user2fa',
        },
        headers: {
          'Content-Type': 'application/json',
          cookie: csrf_headers,
        },
      };

      request(auth_page, function(error, response) {
        should.not.exist(error);
        response.statusCode.should.equal(200);
        done();
      });
    });

    it('should return an input to insert a code', function(done) {
      const auth_page = {
        url: config.host + '/auth/login',
        method: 'POST',
        json: {
          _csrf: csrf_token,
          email: 'user_2fa@test.com',
          password: 'user2fa',
        },
        headers: {
          'Content-Type': 'application/json',
          cookie: csrf_headers,
        },
      };

      request(auth_page, function(error, response) {
        should.not.exist(error);

        const dom = new JSDOM(response.body);
        code = dom.window.document.querySelector("input[name='token']");
        code.nodeName.should.equal('INPUT');

        done();
      });
    });
  });

  describe('3) When sending an invalid code to /auth/tfa_verify', function() {
    let csrf_token;
    let csrf_headers;

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

    it('should return again an input to insert the code', function(done) {
      const send_token = {
        url: config.host + '/auth/tfa_verify',
        method: 'POST',
        json: {
          _csrf: csrf_token,
          user_id,
          token: '111111',
        },
        headers: {
          'Content-Type': 'application/json',
          cookie: csrf_headers,
        },
      };

      request(send_token, function(error, response) {
        should.not.exist(error);
        response.statusCode.should.equal(200);

        const dom = new JSDOM(response.body);
        code = dom.window.document.querySelector("input[name='token']");
        code.nodeName.should.equal('INPUT');

        done();
      });
    });
  });

  describe('4) When sending an invalid security question to /auth/security_question page after sign in', function() {
    let csrf_token;
    let csrf_headers;

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

    it('should return again inputs to insert questions', function(done) {
      const send_question = {
        url: config.host + '/auth/tfa_verify',
        method: 'POST',
        json: {
          _csrf: csrf_token,
          user_id,
          login_security_question: true,
          security_question: 'bbbb',
          security_answer: 'bbbb',
        },
        headers: {
          'Content-Type': 'application/json',
          cookie: csrf_headers,
        },
      };

      request(send_question, function(error, response) {
        should.not.exist(error);
        response.statusCode.should.equal(200);

        const dom = new JSDOM(response.body);
        const question = dom.window.document.querySelector(
          "input[name='security_question']"
        );
        question.nodeName.should.equal('INPUT');
        const answer = dom.window.document.querySelector(
          "input[name='security_answer']"
        );
        answer.nodeName.should.equal('INPUT');

        done();
      });
    });
  });

  describe('5) When sending a valid security question to /auth/security_question page after sign in', function() {
    let csrf_token;
    let csrf_headers;

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

    it('should redirect to /idm', function(done) {
      const send_question = {
        url: config.host + '/auth/tfa_verify',
        method: 'POST',
        json: {
          _csrf: csrf_token,
          user_id,
          login_security_question: true,
          security_question: 'aaaa',
          security_answer: 'aaaa',
        },
        headers: {
          'Content-Type': 'application/json',
          cookie: csrf_headers,
        },
      };

      request(send_question, function(error, response) {
        should.not.exist(error);
        response.statusCode.should.equal(302);
        response.headers.location.should.equal('/idm');
        done();
      });
    });
  });
});
