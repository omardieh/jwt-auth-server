const authRouter = require("express").Router();
const User = require("../models/User.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const isAuthenticated = require("../middleware/isAuthenticated");

authRouter.post("/auth/signup", async (req, res, next) => {
  const { email, password, username } = req.body;
  if (!email || !password || !username) {
    res.json({ error: "all inputs are required" });
    return;
  }
  try {
    const foundUser = await User.findOne({ email });
    if (foundUser) {
      res.json({ error: "User is already registered" });
      return;
    }
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const createdUser = await User.create({ email, username, password: hash });
    res.json(createdUser);
  } catch (err) {
    next(err);
  }
});

authRouter.post("/auth/login", async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.json({ error: "all inputs are required" });
    return;
  }
  try {
    const foundUser = await User.findOne({ email });
    if (!foundUser) {
      res.json({ error: "User does not exist" });
      return;
    }
    const isPasswordMatch = await bcrypt.compare;
    if (!isPasswordMatch) {
      res.json({ error: "Wrong password" });
      return;
    }
    const { password, __v, ...payload } = foundUser.toObject();

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "6h",
    });

    res.json(token);
  } catch (err) {
    next(err);
  }
});

authRouter.get("/auth/verify", isAuthenticated, (req, res) => {
  res.json(req.user);
});

module.exports = authRouter;
