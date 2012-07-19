(function () {

  // internal verifier collection. Never published.
  Meteor.accounts._srpChallenges = new Meteor.Collection(
    "accounts._srpChallenges",
    null /*manager*/,
    null /*driver*/,
    true /*preventAutopublish*/);


  Meteor.methods({
    beginSrp: function (request) {
      var username = request.username;
      if (!username)
        throw new Meteor.Error("must provide a username");

      var user = Meteor.users.findOne({username: username});
      if (!user || !user.services || !user.services.srp)
        throw new Meteor.Error("user not found");
      var verifier = user.services.srp;

      var srp = new Meteor._srp.Server(verifier);
      var challenge = srp.issueChallenge(request);

      // XXX It would be better to put this on the session
      // somehow. However, this gets complicated when interacting with
      // reconnect on the client. The client should detect the reconnect
      // and re-start the exchange.
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

    var serialized = Meteor.accounts._srpChallenges.findOne(
      {M: options.srp.M});
    if (!serialized)
      throw new Meteor.Error("bad password");

    var userId = serialized.userId;
    var loginToken = Meteor.accounts._loginTokens.insert({userId: userId});

    return {token: loginToken, id: userId, srp: {HAMK: serialized.HAMK}};
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

    var user = {username: username, services: {srp: options.newUser.verifier}};
    var userId = Meteor.users.insert(user);

    var loginToken = Meteor.accounts._loginTokens.insert({userId: userId});

    return {token: loginToken, id: userId};
  });



})();
