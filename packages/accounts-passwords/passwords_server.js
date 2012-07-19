(function () {

  // internal verifier collection. Never published.
  Meteor.accounts._srpChallenges = new Meteor.Collection(
    "accounts._srpChallenges",
    null /*manager*/,
    null /*driver*/,
    true /*preventAutopublish*/);


  Meteor.methods({
    // @param request {Object} with fields:
    //   user: either {username: (username)} or {email: (email)}
    //   A: hex encoded int. the client's public key for this exchange
    // @returns {Object} with fields:
    //   identiy: string uuid
    //   salt: string uuid
    //   B: hex encoded int. server's public key for this exchange
    beginPasswordExchange: function (request) {
      if (!request.user)
        throw new Meteor.Error("Must pass a user property in request");

      var username = request.user.username;
      var email = request.user.email;

      if (!username && !email)
        throw new Meteor.Error("Must pass either username or email in request.user");
      if (username && email)
        throw new Meteor.Error("Can't pass both username and email in request.user");

      var selector;
      if (username)
        selector = {username: username};
      else /* if (email) */
        selector = {emails: email};

      var user = Meteor.users.findOne(selector);
      if (!user)
        throw new Meteor.Error("user not found");
      if (!user.services || !user.services.password ||
          !user.services.password.srp)
        throw new Meteor.Error("user has no password set");

      var verifier = user.services.password.srp;
      var srp = new Meteor._srp.Server(verifier);
      var challenge = srp.issueChallenge({A: request.A});

      // XXX It would be better to put this on the session
      // somehow. However, this gets complicated when interacting with
      // reconnect on the client. The client should detect the reconnect
      // and re-start the exchange.
      // https://app.asana.com/0/988582960612/1278583012594
      //
      // Instead we store M and HAMK from SRP (abstraction violation!)
      // and let any session login if it knows M. This is somewhat
      // insecure, if you don't use SSL someone can sniff your traffic
      // and then log in as you (but no more insecure than reconnect
      // tokens).
      var serialized = { userId: user._id, M: srp.M, HAMK: srp.HAMK };
      Meteor.accounts._srpChallenges.insert(serialized);

      return challenge;
    }
  });

  // handler to login with password
  Meteor.accounts.registerLoginHandler(function (options) {
    if (!options.srp)
      return undefined; // don't handle
    if (!options.srp.M)
      throw new Meteor.Error("must pass M in options.srp");

    var serialized = Meteor.accounts._srpChallenges.findOne(
      {M: options.srp.M});
    if (!serialized)
      throw new Meteor.Error("bad password");

    var userId = serialized.userId;
    var loginToken = Meteor.accounts._loginTokens.insert({userId: userId});

    // XXX we should remove srpChallenge documents from mongo, but we
    // need to make sure reconnects still work (meaning we can't
    // remove them right after they've been used). This will also be
    // fixed if we store challenges in session.
    // https://app.asana.com/0/988582960612/1278583012594

    return {token: loginToken, id: userId, HAMK: serialized.HAMK};
  });


  // handler to login with a new user
  Meteor.accounts.registerLoginHandler(function (options) {
    if (!options.newUser)
      return undefined; // don't handle

    if (!options.newUser.username)
      throw new Meteor.Error("need to set a username");
    var username = options.newUser.username;

    if (Meteor.users.findOne({username: username}))
      throw new Meteor.Error("user already exists");

    // XXX validate verifier

    // XXX use updateOrCreateUser

    var user = {username: username, services: {password: {srp: options.newUser.verifier}}};
    var userId = Meteor.users.insert(user);

    var loginToken = Meteor.accounts._loginTokens.insert({userId: userId});

    return {token: loginToken, id: userId};
  });



})();
