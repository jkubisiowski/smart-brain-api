const handleSignin = (db, bcrypt, req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return Promise.reject('incorrect form submission');
  }
  return db
    .select('email', 'hash')
    .from('login')
    .where('email', '=', email)
    .then(data => {
      const isValid = bcrypt.compareSync(password, data[0].hash);
      if (isValid) {
        return db
          .select('*')
          .from('users')
          .where('email', '=', email)
          .then(user => user[0])
          .catch(err => Promise.reject('unable to get user'));
      } else {
        Promise.reject('wrong credentials');
      }
    })
    .catch(err => Promise.reject('wrong credentials'));
};

const getAuthTokenId = () => {
  console.log('ok');
};

const signinAuthentication = (db, bcrypt) => (req, res) => {
  const { authorization } = req.headers;
  return authorization
    ? getAuthTokenId()
    : handleSignin(db, bcrypt, req, res)
        .then(data => res.status(200).json(data))
        .catch(error => res.status(400).json(error));
};

module.exports = {
  signinAuthentication: signinAuthentication
};
