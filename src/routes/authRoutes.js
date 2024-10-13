import { Router } from "express";
import passport from "passport";
import {
  register,
  login,
  logout,
  setup2FA,
  verify2FA,
  reset2FA,
} from "../controllers/authController";

const router = Router();

// registeration route
router.post("/register", register);
// login router
router.post("/login", passport.authenticate("local"), login);
// auth status route
router.get("/status", authStatus);
// logout route
router.post("/logout", logout);

//2FA setup
router.post(
  "/2fa/setup",
  (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ message: "unauthorized" });
  },
  setup2FA
);
// verify route
router.get(
  "/2fa/verify",
  (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ message: "unauthorized" });
  },
  verify2FA
);
// logout route
router.post(
  "/2fa/reset",
  (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ message: "unauthorized" });
  },
  reset2FA
);

export default router;
