const bcrypt = require('bcryptjs');

const User = require('../models/user');

module.exports = {
  createUser: async function(args, req) {
    const { email, name, password } = args.userInput;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      const error = new Error('User exists already');
      throw error;
    }
    const hashedPw = await bcrypt.hash(password, 12);
    const user = new User({
      email,
      name,
      password: hashedPw,
    });
    const createdUser = await user.save();
    return {
      ...createdUser._doc,
      _id: createdUser._id.toString(), // I have to convert it to string and save it again, otherwise it will fail
    }
  }
}