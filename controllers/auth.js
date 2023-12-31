import users from "../models/user.js";
import OTPModel from "../models/otp.js";
import { sendMail } from "../lib/helpers.js";
import jwt from "jsonwebtoken";
import Joi from "joi";
import bcrypt from "bcrypt";
import otpGenerator from "otp-generator";

//LOGIN
export const loginUser = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader) {
      const token = authHeader.split(" ")[1];
      jwt.verify(token, process.env.JWT_SECRET, (error, decoded) => {
        if (error) {
          return res.status(403).send(error);
        }
        req.user = decoded;
        return res.status(200).json("Success");
      });
    }

    //Form Validation
    const loginSchema = Joi.object({
      email: Joi.string().required(),
      password: Joi.string().required(),
    });
    await loginSchema.validateAsync(req.body);

    //Search in DB
    const { email, password } = req.body;
    const user = await users.findOne({ email });

    if (!user) {
      return res.status(404).send("Not registered!");
    }

    //Verify Password
    const passwordCorrect = await bcrypt.compare(password, user.password);
    if (passwordCorrect) {
      const accessToken = jwt.sign(
        { name: user.name, email, role: user.role },
        process.env.JWT_SECRET,
        {
          expiresIn: "72h",
        }
      );

      return res.status(200).json({ email, accessToken });
    } else {
      return res.status(400).send("Wrong Password");
    }
  } catch (error) {
    if (error.details) {
      return res
        .status(422)
        .json(error.details.map((detail) => detail.message).join(", "));
    }

    return res.status(500).send(error.message);
  }
};

export const isRegistered = async (req, res) => {
  try {
    const email = req.body.email;

    // isRegistered
    const user = await users.findOne({ email }, { _id: 0, username: 1 });
    if (user) {
      return res.status(200).send(true);
    } else {
      return res.status(200).send(false);
    }
  } catch (error) {
    return res.status(500).json(error.message);
  }
};

//SEND OTP
export const sendOTP = async (req, res) => {
  try {
    if (!req.body.email) {
      return res.status(400).json("No email provided!");
    }

    // Verify JWT for authentication
    const token = req.headers.authorization;
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (decoded.username) {
        return res.status(403).json("Already logged in");
      }
    }

    // Email Validation
    const emailSchema = Joi.object({
      email: Joi.string().email().required(),
    });
    await emailSchema.validateAsync({ email: req.body.email });

    // Generate OTP and store in MongoDB
    const otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });

    const expiry = new Date();
    expiry.setSeconds(expiry.getSeconds() + 300); // 5 minutes expiration

    const otpData = new OTPModel({
      email: req.body.email,
      otp,
      expiry,
    });

    await otpData.save();

    const mailOptions = {
      from: process.env.GMAIL_ID,
      to: req.body.email,
      subject: `facOTTry - Your OTP for verification is ${otp}`,
      html: `<p>Hello,</p>
             <p>Your OTP for verification is: <strong>${otp}</strong></p>
             <p>Thank you for using facOTTry!</p>`,
    };

    const result = await sendMail(mailOptions);
    if (result.accepted) return res.json(result);

    res.status(500).send("Error sending OTP");
  } catch (error) {
    if (error.details) {
      return res
        .status(422)
        .json(error.details.map((detail) => detail.message).join(", "));
    }

    return res.status(500).json(error.message);
  }
};

//VERIFY OTP
export const verifyOTP = async (req, res) => {
  try {
    // Check login status
    const token = req.headers.authorization;
    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (decoded.username) {
        return res.status(403).json("Already logged in");
      }
    }

    const userEnteredOTP = req.body.otp;

    // Master OTP
    if (userEnteredOTP === "998877") {
      jwt.sign(
        { email: req.body.email },
        process.env.JWT_SECRET,
        { expiresIn: "5m" },
        (error, token) => {
          if (error) {
            return res.status(500).json(error.message);
          }

          return res.status(200).json({ temp_token: token });
        }
      );
    } else {
      // Verify OTP for normal users
      const storedOTP = await OTPModel.findOne({
        email: req.body.email,
      }).sort({ _id: -1 });

      if (!storedOTP) {
        return res.status(401).send("OTP not generated or expired");
      }

      if (storedOTP.otp === userEnteredOTP) {
        jwt.sign(
          { email: req.body.email },
          process.env.JWT_SECRET,
          { expiresIn: "5m" },
          (error, token) => {
            if (error) {
              return res.status(500).json(error.message);
            }

            return res.status(200).json({ temp_token: token });
          }
        );
      } else {
        return res.status(403).send("Wrong OTP");
      }
    }
  } catch (error) {
    return res.status(500).json(error.message);
  }
};

//REGISTER
export const registerUser = async (req, res) => {
  try {
    //Request Body Validation
    const registerSchema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().pattern(
        new RegExp("^(?=.*[A-Za-z])(?=.*[0-9])[a-zA-Z0-9@$!%*#?&]{8,}$")
      ),
    });
    await registerSchema.validateAsync(req.body);

    const { email, password } = req.body;

    // Hash password & save to mongoDB
    const hash = await bcrypt.hash(password, 10);
    const newUser = new users({
      email,
      password: hash,
    });
    await newUser.save();

    const accessToken = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });

    return res.status(200).json({ email, accessToken });
  } catch (error) {
    if (error.details) {
      return res
        .status(422)
        .json(error.details.map((detail) => detail.message).join(", "));
    }

    return res.status(500).json(error.message);
  }
};