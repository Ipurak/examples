const jwt = require('jsonwebtoken');

// Set in `environment` of serverless.yml
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const AUTH0_CLIENT_PUBLIC_KEY = process.env.AUTH0_CLIENT_PUBLIC_KEY;

// Policy helper function
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};

// Reusable Authorizer function, set on `authorizer` field in serverless.yml
module.exports.auth = (event, context, callback) => {

  console.log('event', event);

  // event.authorizationToken = 'bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJqazFOelV6UXpBNU5rRkNSREV3UkVRM09FRTFPVFZCTnpFelJqaENRemMwUVRVelF6ZzVNQSJ9.eyJlbWFpbCI6ImFzbWkucnVuZ3JvdEBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9kZXYtZTU3NHBqdmYuYXV0aDAuY29tLyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTE4MTgxODI4Nzc0MDMyMzIwMjM2IiwiYXVkIjoicE5WRUZNZXdKektPdGpoV3ZibkF5ZDNCVURlQ0U0MGciLCJpYXQiOjE1NjY5NzYxNjgsImV4cCI6MTU2NzAxMjE2OCwiYXRfaGFzaCI6IlpsWDFfcVdYN19wc2RxNE1EU1U4RkEiLCJub25jZSI6ImZra3VUWjhSakdBRzZxZFVqZ2ZWMGtBdkREdFZ1NVRvIn0.Rt3uRUPXtcvvIIBLfvX_2aawbbhm3JPUPWKUI1uHXDUZkkzTKvqqgcPnDXdSsrWM585unRxkJJTXtpDgkV_5izG7oRbAWsgEp1oYrfnJxZms6pMGGDBk7gJHC58V0K8lgZJ-uYKqFfITvMg2npv1iq74mBFiDINYH_EQAxLjbKWbkiDmqzhgexe3_lkWoPSBHLd-KBtr_YFbXTc1aDxX5bQE4LCFO6god2wqrbw0GCGcgq_zdtY_BxYDNQifNXIg2eLZjLh-byZRNSC7GbOzKgdRDaMOpLMnuUgAJt5Hosy4bE1wJUz8ERLiu7PtT9OFlc7GeE02aEWYiQykv91hpQ';

  if (!event.authorizationToken) {
    return callback(null, {
      statusCode: 400,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': true,
      },
      body: JSON.stringify({
        message: 'Unauthorized1',
      }),
    });
  }

  const tokenParts = event.authorizationToken.split(' ');
  const tokenValue = tokenParts[1];

  if (!(tokenParts[0].toLowerCase() === 'bearer' && tokenValue)) {
    // no auth token!
    return callback('Unauthorized2');
  }
  const options = {
    audience: AUTH0_CLIENT_ID,
  };

  try {
    jwt.verify(tokenValue, AUTH0_CLIENT_PUBLIC_KEY, options, (verifyError, decoded) => {
      if (verifyError) {
        console.log('verifyError', verifyError);
        // 401 Unauthorized
        console.log(`Token invalid. ${verifyError}`);
        return callback('Unauthorized3');
      }
      // is custom authorizer function
      console.log('valid from customAuthorizer', decoded);
      return callback(null, generatePolicy(decoded.sub, 'Allow', event.methodArn));
    });
  } catch (err) {
    console.log('catch error. Invalid token', err);
    return callback('Unauthorized4');
  }

};

// Public API
module.exports.publicEndpoint = (event, context, callback) => callback(null, {
  statusCode: 200,
  headers: {
      /* Required for CORS support to work */
    'Access-Control-Allow-Origin': '*',
      /* Required for cookies, authorization headers with HTTPS */
    'Access-Control-Allow-Credentials': true,
  },
  body: JSON.stringify({
    message: 'Hi ⊂◉‿◉つ from Public API',
  }),
});

// Private API
module.exports.privateEndpoint = (event, context, callback) => callback(null, {
  statusCode: 200,
  headers: {
      /* Required for CORS support to work */
    'Access-Control-Allow-Origin': '*',
      /* Required for cookies, authorization headers with HTTPS */
    'Access-Control-Allow-Credentials': true,
  },
  body: JSON.stringify({
    message: 'Hi ⊂◉‿◉つ from Private API. Only logged in users can see this',
  }),
});
