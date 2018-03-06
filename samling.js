var crypto = require('crypto');
var fs = require('fs');
window.CLIPBOARDJS = require('clipboard-js');
window.SAML = require('./saml');
const COOKIE_NAME = 'samling';

function deleteCookie() {
  document.cookie = COOKIE_NAME + '=' + ';path=/;expires=' + (new Date(1));
}

function logout(info) {
  deleteCookie();
  if (info) {
    var delim = info.callbackUrl.indexOf('?') === -1 ? '?' : '&';
    location.href = info.callbackUrl + delim + 'SAMLResponse=' + encodeURIComponent(btoa(info.response));
  } else {
    location.href = location.href.replace(location.search, '');
  }
}

function handleRequest(request, relayState) {
  // parse the saml request
  window.SAML.parseRequest({issuer: $('#issuer').val().trim(), callbackUrl: $('#callbackUrl').val().trim()}, request, function(info) {
    if (info.logout) {
      logout(info.logout);
      return;
    }

    // populate fields from the request
    $('#authnContextClassRef').val(info.login.authnContextClassRef);
    $('#nameIdentifierFormat').val(info.login.nameIdentifierFormat);
    $('#callbackUrl').val(info.login.callbackUrl);
    $('#issuer').val(info.login.destination);
    $('#relayState').val(decodeURIComponent(relayState));

    // auto-login if we also have the username already populated because of the samling cookie
    if ($('#signedInUser').text().trim().length > 0) {
      $('#createResponse').trigger('click');
      setTimeout(function() {
        $('#postSAMLResponse').trigger('click');
      }, 100);
    }
  });
}


$(function() {

  $('[data-toggle="tooltip"]').tooltip();
  $('[data-toggle="popover"]').popover();

  $('#signatureCert').val(localStorage.getItem('certVal') || fs.readFileSync('./cert.pem'));
  $('#signatureKey').val(localStorage.getItem('privateKeyVal') || fs.readFileSync('./key.pem'));

  var userControl = $('#signedInUser');
  var cookies = document.cookie.split(';');
  cookies.forEach(function(cook) {
    var parts = cook.split('=');
    if (parts[0].trim() === COOKIE_NAME) {
      try {
        var value = atob(parts[1].trim());
        var data = JSON.parse(value);
        userControl.text('Hello ' + data.nameIdentifier);
        $('#signedInAt').text(data.signedInAt);
        $('#nameIdentifier').val(data.nameIdentifier);
        $('#callbackUrl').val(data.callbackUrl);
        $('#issuer').val(data.issuer);
        $('#authnContextClassRef').val(data.authnContextClassRef);
        $('#nameIdentifierFormat').val(data.nameIdentifierFormat);
      } catch (e) {
        $('#signedInAt').text('ERROR: ' + e.message);
      }
    }
  });

  $('#copyResponseToClipboard').click(function() {
    window.CLIPBOARDJS.copy($('#samlResponse').val());
    $('#copyResponseToClipboard').tooltip('show');
    setTimeout(function() {
      $('#copyResponseToClipboard').tooltip('hide');
    }, 1500);
  });

  $('#signedInLogout').click(function() {
    logout();
  });

  $('#generateKeyAndCert').click(function() {
    var pki = window.forge.pki;
    var keypair = pki.rsa.generateKeyPair({bits: 1024});
    var cert = pki.createCertificate();
    cert.publicKey = keypair.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    var attrs = [{
      name: 'commonName',
      value: 'capriza.com'
    }, {
      name: 'countryName',
      value: 'US'
    }, {
      shortName: 'ST',
      value: 'Virginia'
    }, {
      name: 'localityName',
      value: 'Blacksburg'
    }, {
      name: 'organizationName',
      value: 'Samling'
    }, {
      shortName: 'OU',
      value: 'Samling'
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([{
      name: 'basicConstraints',
      cA: true
    }, {
      name: 'keyUsage',
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true
    }, {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
      codeSigning: true,
      emailProtection: true,
      timeStamping: true
    }, {
      name: 'nsCertType',
      client: true,
      server: true,
      email: true,
      objsign: true,
      sslCA: true,
      emailCA: true,
      objCA: true
    }, {
      name: 'subjectAltName',
      altNames: [{
        type: 6, // URI
        value: 'http://capriza.com/samling'
      }]
    }, {
      name: 'subjectKeyIdentifier'
    }]);
    // self-sign certificate
    cert.sign(keypair.privateKey);
    // convert to PEM
    var certVal = pki.certificateToPem(cert);
    var privateKeyVal = pki.privateKeyToPem(keypair.privateKey);
    $('#signatureCert').val(certVal);
    $('#signatureKey').val(privateKeyVal);
  });

  $('#saveKeyAndCert').click(function() {
    localStorage.setItem('certVal', $('#signatureCert').val().trim());
    localStorage.setItem('privateKeyVal', $('#signatureKey').val().trim());
  });

  $('#createResponse').click(function() {
    $('#nameIdentifierControl').removeClass('has-error');
    $('#callbackUrlControl').removeClass('has-error');
    $('#signatureKeyControl').removeClass('has-error');
    $('#signatureCertControl').removeClass('has-error');

    var error = false;
    if ($('#nameIdentifier').val().trim().length === 0) {
      $('#nameIdentifierControl').addClass('has-error');
      !error && $('#nameIdentifier').focus();
      error = true;
    }

    if ($('#callbackUrl').val().trim().length === 0) {
      $('#callbackUrlControl').addClass('has-error');
      !error && $('#callbackUrl').focus();
      error = true;
    }

    if ($('#signatureKey').val().trim().length === 0) {
      $('#signatureKeyControl').addClass('has-error');
      !error && $('#signatureKey').focus();
      error = true;
    }

    if ($('#signatureCert').val().trim().length === 0) {
      $('#signatureCertControl').addClass('has-error');
      !error && $('#signatureCert').focus();
      error = true;
    }

    if (error) {
      return;
    }

    var attributes = undefined;
    var attributesStr = $('#samlAttributes').val().trim();
    if (attributesStr.length > 0) {
      attributes = {};
      attributesStr.split('\n').forEach(function(line) {
        var line = line.split('=');
        var name = line.shift().trim();
        if (name.length > 0) {
          attributes[name] = (line.join('=')).trim();
        }
      });
    }

    var options = {
      key: $('#signatureKey').val().trim(),
      cert: $('#signatureCert').val().trim(),
      issuer: $('#issuer').val().trim(),
      authnContextClassRef: $('#authnContextClassRef').val().trim(),
      nameIdentifierFormat: $('#nameIdentifierFormat').val().trim(),
      nameIdentifier: $('#nameIdentifier').val().trim(),
      sessionIndex: ('_samling_' + (Math.random() * 10000000)).replace('.', '_'),
      attributes: attributes
    };
    var assertion = window.SAML.createAssertion(options);
    var callbackUrl = $('#callbackUrl').val().trim();
    var destinationUrl = $('#destinationUrl').val().trim();
    var response = window.SAML.createResponse({
      instant: new Date().toISOString().trim(),
      issuer: $('#issuer').val().trim(),
      callback: callbackUrl,
      destination: destinationUrl,
      assertion: assertion,
      samlStatusCode: $('#samlStatusCode').val().trim(),
      samlStatusMessage: $('#samlStatusMessage').val().trim()
    });
    $('#samlResponse').val(response);
    $('#callbackUrlReadOnly').val(callbackUrl);
    $('#navbarSamling a[href="#samlResponseTab"]').tab('show')
  });

  $('#postSAMLResponse').click(function(event) {
    event.preventDefault();
    $('#samlResponseControl').removeClass('has-error');
    $('#sessionDurationControl').removeClass('has-error');
    $('#callbackUrlControl').removeClass('has-error');

    var error = false;

    var samlResponse = $('#samlResponse').val().trim();
    if (samlResponse.length === 0) {
      $('#samlResponseControl').addClass('has-error');
      !error && $('#samlResponse').focus();
      error = true;
    }
    $('#samlResponse').val(btoa(samlResponse));

    var sessionDuration = $('#sessionDuration').val().trim();
    if (sessionDuration.length === 0) {
      $('#sessionDurationControl').addClass('has-error');
      !error && $('#sessionDuration').focus();
      error = true;
    } else if (!sessionDuration.match(/^\d+$/)) {
      error && $('#sessionDuration').focus();
      error = true;
    }

    var callbackUrl = $('#callbackUrl').val().trim();
    if (callbackUrl.length === 0) {
      $('#callbackUrlControl').addClass('has-error');
      !error && $('#callbackUrl').focus();
      error = true;
    }

    if (error) {
      return;
    }

    // write the "login" cookie
    var expires = '';
    if (sessionDuration !== '0') {
      expires = 'expires=' + new Date(Date.now() + parseInt(sessionDuration) * 1000 * 60).toUTCString();
    }

    var cookieData = {
      signedInAt: new Date().toUTCString(),
      nameIdentifier: $('#nameIdentifier').val().trim(),
      callbackUrl: $('#callbackUrl').val().trim(),
      issuer: $('#issuer').val().trim(),
      authnContextClassRef: $('#authnContextClassRef').val().trim(),
      nameIdentifierFormat: $('#nameIdentifierFormat').val().trim()
    };
    var cookieValue = btoa(JSON.stringify(cookieData));
    deleteCookie();
    document.cookie = COOKIE_NAME + '=' + cookieValue + ';path=/;' + expires;

    var form = $('#samlResponseForm')[0];
    form.action = callbackUrl;
    form.submit();
  });

  if (location.search.indexOf('SAMLRequest=') !== -1) {
    var params = location.search.split('?');
    if (params.length > 1) {
      var params = params[1].split('&');
      var query = {};
      params.forEach(function(part) {
        var keyval = part.split('=');
        query[keyval[0]] = keyval[1];
      });
      handleRequest(query['SAMLRequest'], query['RelayState']);
    }
  }

});

