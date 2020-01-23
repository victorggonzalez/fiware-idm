/*
 * Copyright 2019 -  Universidad Politécnica de Madrid.
 *
 * This file is part of Keyrock
 *
 */

// Load database configuration before
require('../../config/config_database');

// const keyrock = require('../../bin/www');
const config = require('../../../config.js');
const should = require('should');
const request = require('request');
const utils = require('../../utils');

const login = utils.readExampleFile(
  './test/templates/api/000-authenticate.json'
).good_admin_login;
const organizations = utils.readExampleFile(
  './test/templates/api/004-organizations.json'
);

let token;

describe('API - 4 - Organizations: ', function() {
  // CREATE A VALID TOKEN
  // eslint-disable-next-line no-undef
  before(function(done) {
    const good_login = {
      url: config.host + '/v1/auth/tokens',
      method: 'POST',
      json: login,
      headers: {
        'Content-Type': 'application/json',
      },
    };
    return request(good_login, function(error, response) {
      token = response.headers['x-subject-token'];
      done();
    });
  });

  describe('1) When requesting list of organizations', function() {
    it('should return a 200 OK', function(done) {
      const list_organizations = {
        url: config.host + '/v1/organizations',
        method: 'GET',
        headers: {
          'X-Auth-token': token,
        },
      };
      request(list_organizations, function(error, response, body) {
        should.not.exist(error);
        const json = JSON.parse(body);
        should(json).have.property('organizations');
        response.statusCode.should.equal(200);
        done();
      });
    });
  });

  describe('2) When creating an organization', function() {
    it('should return a 201 OK', function(done) {
      const create_organization = {
        url: config.host + '/v1/organizations',
        method: 'POST',
        body: JSON.stringify(organizations.create.valid_org_body),
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-token': token,
        },
      };

      request(create_organization, function(error, response, body) {
        should.not.exist(error);
        const json = JSON.parse(body);
        should(json).have.property('organization');
        response.statusCode.should.equal(201);
        done();
      });
    });
  });

  describe('3) When reading organization info', function() {
    let organization_id;

    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const create_organization = {
        url: config.host + '/v1/organizations',
        method: 'POST',
        body: JSON.stringify(organizations.read.create),
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-token': token,
        },
      };

      request(create_organization, function(error, response, body) {
        const json = JSON.parse(body);
        organization_id = json.organization.id;
        done();
      });
    });

    it('should return a 200 OK', function(done) {
      const read_organization = {
        url: config.host + '/v1/organizations/' + organization_id,
        method: 'GET',
        headers: {
          'X-Auth-token': token,
        },
      };

      request(read_organization, function(error, response, body) {
        should.not.exist(error);
        const json = JSON.parse(body);
        should(json).have.property('organization');
        response.statusCode.should.equal(200);
        done();
      });
    });
  });

  describe('4) When updating an organization', function() {
    let organization_id;
    let organization_name;

    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const create_organization = {
        url: config.host + '/v1/organizations',
        method: 'POST',
        body: JSON.stringify(organizations.update.create),
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-token': token,
        },
      };

      request(create_organization, function(error, response, body) {
        const json = JSON.parse(body);
        organization_id = json.organization.id;
        organization_name = json.organization.name;
        done();
      });
    });

    it('should return a 200 OK', function(done) {
      const update_organization = {
        url: config.host + '/v1/organizations/' + organization_id,
        method: 'PATCH',
        body: JSON.stringify(organizations.update.new_values),
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-token': token,
        },
      };

      request(update_organization, function(error, response, body) {
        should.not.exist(error);
        const json = JSON.parse(body);
        should(json).have.property('values_updated');
        const response_name = json.values_updated.name;
        should.notEqual(organization_name, response_name);
        response.statusCode.should.equal(200);
        done();
      });
    });
  });

  describe('4) When deleting an organization', function() {
    let organization_id;

    // eslint-disable-next-line snakecase/snakecase
    beforeEach(function(done) {
      const create_organization = {
        url: config.host + '/v1/organizations',
        method: 'POST',
        body: JSON.stringify(organizations.delete.create),
        headers: {
          'Content-Type': 'application/json',
          'X-Auth-token': token,
        },
      };

      request(create_organization, function(error, response, body) {
        const json = JSON.parse(body);
        organization_id = json.organization.id;
        done();
      });
    });

    it('should return a 204 OK', function(done) {
      const delete_organization = {
        url: config.host + '/v1/organizations/' + organization_id,
        method: 'DELETE',
        headers: {
          'X-Auth-token': token,
        },
      };

      request(delete_organization, function(error, response) {
        should.not.exist(error);
        response.statusCode.should.equal(204);
        done();
      });
    });
  });
});
