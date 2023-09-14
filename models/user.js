const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserSchema = new Schema(
  {
    username: {
      type: String,
      requred: true,
    },
    email: {
      type: String,
      requred: true,
    },
    password: {
      type: String,
      requred: true,
    },
    password2: {
      type: String,
      requred: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    collection: "users",
  }
);

module.exports = User = mongoose.model("User", UserSchema);
