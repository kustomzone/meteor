(function () {

  // XXX options to add to new user
  // XXX callback
  Meteor.loginNewUser = function (username, password, callback) {
    var verifier = Meteor._srp.generateVerifier(password);

    Meteor.apply('login', [
      {newUser: {username: username, verifier: verifier}}
    ], {wait: true}, function (error, result) {
      if (error || !result) {
        error = error || new Error("No result");
        callback && callback(error);
        return;
      }

      Meteor.accounts.makeClientLoggedIn(result.id, result.token);
      callback && callback(null, {message: 'Success'});
    });

  };

  // @param selector {String|Object} One of the following:
  //   - {username: (username)}
  //   - {email: (email)}
  //   - a string which may be a username or email, depending on whether
  //     it contains "@".
  // @param password {String}
  // @param callback {Function(error|undefined)}
  Meteor.loginWithPassword = function (selector, password, callback) {
    var srp = new Meteor._srp.Client(password);
    var request = srp.startExchange();

    if (typeof selector === 'string')
      if (selector.indexOf('@') === -1)
        selector = {username: selector};
      else
        selector = {email: selector};
    request.user = selector;

    Meteor.apply('beginPasswordExchange', [request], function (error, result) {
      if (error || !result) {
        error = error || new Error("No result from call to beginPasswordExchange");
        callback && callback(error);
        return;
      }

      var response = srp.respondToChallenge(result);
      Meteor.apply('login', [
        {srp: response}
      ], {wait: true}, function (error, result) {
        if (error || !result) {
          error = error || new Error("No result from call to login");
          callback && callback(error);
          return;
        }

        if (!srp.verifyConfirmation({HAMK: result.HAMK})) {
          callback && callback(new Error("Server is cheating!"));
          return;
        }

        Meteor.accounts.makeClientLoggedIn(result.id, result.token);
        callback && callback();
      });
    });
  };
})();
