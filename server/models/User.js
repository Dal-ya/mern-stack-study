const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const moment = require('moment');

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50
  },
  email: {
    type: String,
    trim: true,
    unique: 1
  },
  password: {
    type: String,
    minlength: 5
  },
  lastname: {
    type: String,
    maxlength: 50
  },
  role: {
    type: Number,
    default: 0
  },
  image: String,
  token: {
    type: String
  },
  tokenExp: {
    type: Number
  }
});

userSchema.pre('save', function (next) {
  // this 는 위에 userSchema 를 가리킨다
  var user = this;

  if (user.isModified('password')) {
    // console.log('password changed')
    bcrypt.genSalt(saltRounds, function (err, salt) {
      if (err) return next(err);

      bcrypt.hash(user.password, salt, function (err, hash) {
        if (err) return next(err);
        user.password = hash;
        next();
      });
    });
  } else {
    next();
  }
});

// methods 는 mongoose 에서 제공하는 메서드이다. 사용자 정의 메서드를 만들 수 있다.
// routes/users.js 에서 활용하는 것을 참고하자.
// isMatch 는 패스워드가 일치하면 true, 아니면 false 를 반환한다.
userSchema.methods.comparePassword = function (plainPassword, cb) {
  bcrypt.compare(plainPassword, this.password, function (err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

userSchema.methods.generateToken = function (cb) {
  // this 는 위에 userSchema 를 가리킨다
  var user = this;

  // toHexString() 은 몽구스에서 제공하는 메서드이다.
  // Return the ObjectID id as a 24 byte hex string representation
  // jwt.sign 의 첫번째 파라미터의 타입은 스트링이어야 한다.
  // user._id 의 타입을 스트링으로 변경해주어야 한다.
  // toString() or toHexString() 을 해주어야 한다.

  // jwt.sign(user._id, 'shh') -> ({_id:user._id...}) 이렇게 사용해야 jwt.io에서 디코드할 때 명확하게 알 수 있다.
  var token = jwt.sign({ _id: user._id.toHexString() }, 'secret');
  var oneHour = moment().add(1, 'hour').valueOf();

  user.tokenExp = oneHour;
  user.token = token;
  user.save(function (err, user) {
    if (err) return cb(err);
    cb(null, user);
  });
};

// statics 를 사용하면 static function 을 만든다라고 되어 있는데...
// 클래스에서 사용하는 static 가 같은 개념인 것 같다
// 그래서 User.findByToken 형태로 사용할 수 있다.
// 스태틱이 아닌 일반 메소드이면 user.xxx 이런 인스턴스에서 사용할 수 있다.
userSchema.statics.findByToken = function (token, cb) {
  var user = this;

  jwt.verify(token, 'secret', function (err, decode) {
    // console.log('decode:::', decode);
    user.findOne({ _id: decode._id, token: token }, function (err, user) {
      if (err) return cb(err);
      cb(null, user);
    });
  });
};

const User = mongoose.model('User', userSchema);

module.exports = { User };
