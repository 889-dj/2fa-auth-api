import bcypt from "bcryptjs";
import User from "../models/user.js";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcypt.hash(password, 10);
    const newUser = new User({
      username,
      password: hashedPassword,
      isMfaActive: false,
    });
    console.log(`new user: ${newUser}`);
    await newUser.save();
    res.status(201).json({ message: "user registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "error registering user", message: error });
  }
};

export const login = async (req, res) => {
  console.log(`the authenticated user is: ${req.user}`);
  res.status(200).json({
    message: "user logged in successfully",
    username: req.user.username,
    isMfaActive: req.user.isMfaActive,
  });
};

export const authStatus = async (req, res) => {
  if (req.user) {
    res.status(200).json({
      message: "user logged in successfully",
      username: req.user.username,
      isMfaActive: req.user.isMfaActive,
    });
  } else {
    res.status(401).json({ message: "unauthorised user" });
  }
};

export const logout = async (req, res) => {
  if (!req.user) res.status(401).json({ message: "unauthorised user" });
  req.logout((err) => {
    if (err) return res.status(400).json({ message: "user not loggedin" });
    res.status(200).json({ message: "logout successful" });
  });
};

export const setup2FA = async (req, res) => {
  try {
    const user = req.user;
    var secret = speakeasy.generateSecret();
    user.twoFactorSecret = secret.base32;
    user, (isMfaActive = true);
    await user.save();
    const url = speakeasy.otpauthURL({
      secret: secret.base32,
      label: `${req.user.username}`,
      issuer: "www.dev.com",
      encoding: "base32",
    });
    const qrImageUrl = await qrcode.toDataURL(url);
    res.status(200).json({
      secret: secret.base32,
      qrcode: qrImageUrl,
    });
  } catch (error) {
    res.status(500).json({ error: "error setting up 2FA", message: error });
  }
};

export const verify2FA = async (req, res) => {
  const { token } = req.body;
  const user = req.user;
  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: "base32",
    token,
  });
  if (verified) {
    const jwtToken = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1hr" }
    );
    res.status(200).json({ message: "2FA successful", token: jwtToken });
  } else {
    res.status(400).json({ message: "invalid 2FA token" });
  }
};

export const reset2FA = async (req, res) => {
  try {
    const user = req.user;
    user.twoFactorSecret = "";
    user.isMfaActive = false;
    await user.save();
    res.status(200).json({ message: "2FA reset successful" });
  } catch (error) {
    res.status(500).json({ error: "error resetting 2FA", message: error });
  }
};
