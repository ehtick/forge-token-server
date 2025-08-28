/////////////////////////////////////////////////////////////////////
// Copyright (c) Autodesk, Inc. All rights reserved
// Written by Developer Advocacy and Support
//
// Permission to use, copy, modify, and distribute this software in
// object code form for any purpose and without fee is hereby granted,
// provided that the above copyright notice appears in all copies and
// that both that copyright notice and the limited warranty and
// restricted rights notice below appear in all supporting
// documentation.
//
// AUTODESK PROVIDES THIS PROGRAM "AS IS" AND WITH ALL FAULTS.
// AUTODESK SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTY OF
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR USE.  AUTODESK, INC.
// DOES NOT WARRANT THAT THE OPERATION OF THE PROGRAM WILL BE
// UNINTERRUPTED OR ERROR FREE.
/////////////////////////////////////////////////////////////////////

const { AuthenticationClient, Scopes } = require('@aps_sdk/authentication');

const config = require( '../../config' );
const authenticationClient = new AuthenticationClient();

/**
 * Initializes a APS client for 2-legged authentication.
 * @param {string[]} scopes List of resource access scopes.
 * @returns {AuthClientTwoLegged} 2-legged authentication client.
 */
function getClient(scopes) {
  const { client_id, client_secret } = config.credentials;
  return new AuthClientTwoLeggedV2( client_id, client_secret, scopes || config.scopes.internal );
}

function getScopeEnum(scopeString) {
  const reverseScopeMap = {
    "user:read": Scopes.UserRead,
    "user:write": Scopes.UserWrite,
    "user-profile:read": Scopes.UserProfileRead,
    "viewables:read": Scopes.ViewablesRead,
    "data:read": Scopes.DataRead,
    "data:write": Scopes.DataWrite,
    "data:create": Scopes.DataCreate,
    "data:search": Scopes.DataSearch,
    "bucket:create": Scopes.BucketCreate,
    "bucket:read": Scopes.BucketRead,
    "bucket:update": Scopes.BucketUpdate,
    "bucket:delete": Scopes.BucketDelete,
    "code:all": Scopes.CodeAll,
    "account:read": Scopes.AccountRead,
    "account:write": Scopes.AccountWrite,
    "openid": Scopes.OpenId
  };
  return reverseScopeMap[scopeString] || null;
}

let cache = {};
async function getToken( scopes ) {
  const key = scopes.join( '+' );
  if( cache[key] ) {
    return cache[key];
  }

  const { client_id, client_secret } = config.credentials;
  const scopeEnums = scopes.map( getScopeEnum ).filter( s => s !== null );
  let credentials = await authenticationClient.getTwoLeggedToken(
    client_id,
    client_secret,
    scopeEnums
  );
  cache[key] = credentials;
  setTimeout( () => { delete cache[key]; }, credentials.expires_in * 1000 );
  return credentials;
}

/**
 * Retrieves a 2-legged authentication token for preconfigured public scopes.
 * @returns Token object: { "access_token": "...", "expires_at": "...", "expires_in": "...", "token_type": "..." }.
 */
async function getPublicToken() {
  return getToken( config.scopes.public );
}

/**
 * Retrieves a 2-legged authentication token for preconfigured internal scopes.
 * @returns Token object: { "access_token": "...", "expires_at": "...", "expires_in": "...", "token_type": "..." }.
 */
async function getInternalToken() {
  return getToken( config.scopes.internal );
}

module.exports = {
  getClient,
  getPublicToken,
  getInternalToken
};
