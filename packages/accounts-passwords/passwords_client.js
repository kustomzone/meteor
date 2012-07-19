(function () {

  // XXX options to add to new user
  // XXX callback
  Meteor.loginNewUser = function (username, password, callback) {
    var verifier = Meteor._srp.generateVerifier(password);

    Meteor.apply('login', [
      {newUser: {username: username, verifier: verifier}}
    ], {wait: true}, function (error, result) {
      if (error) {
        console.log(error);
        callback && callback(error);
        // XXX this hides the error! and we do it other places in auth
        throw error;
      }

      if (!result) {
        return;
      } else {
        Meteor.accounts.makeClientLoggedIn(result.id, result.token);
        callback && callback(null, {message: 'Success'});
      }
    });

  };

  Meteor.loginWithPassword = function (username, password, callback) {
    var srp = new Meteor._srp.Client(password);
    var request = srp.startExchange();

    request.username = username; // XXX
    Meteor.apply('beginSrp', [request], function (error, result) {
      if (error) {
        console.log(error);
        callback && callback(error);
        // XXX this hides the error! and we do it other places in auth
        throw error;
      }

      var response = srp.respondToChallenge(result);
      Meteor.apply('login', [
        {srp: response}
      ], {wait: true}, function (error, result) {
        if (error) {
          callback && callback(error);
          console.log(error);
          // XXX this hides the error! and we do it other places in auth
          throw error;
        }

        if (!result) {
          return;
        }

        if (!srp.verifyConfirmation(result.srp)) {
          console.log('no verify!');
          throw new Meteor.Error("server is cheating!");
        }

        Meteor.accounts.makeClientLoggedIn(result.id, result.token);
        callback && callback(null, {message: "Success"});
      });
    });
  };
})();
