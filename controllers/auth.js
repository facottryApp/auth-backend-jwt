import users from "../models/userModel.js";
import jwt from "jsonwebtoken";
import Joi from 'joi'
import bcrypt from "bcrypt";

//LOGIN
export const loginUser = async (req, res) => {
  try {
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
          expiresIn: "24h",
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

//REGISTER
export const registerUser = async (req, res) => {
  try {
    //Request Body Validation
    const registerSchema = Joi.object({
      name: Joi.string().required(),
      role: Joi.string().required().valid("admin", "user"),
      email: Joi.string().email().required(),
      password: Joi.string().pattern(
        new RegExp(
          "^(?=.*[A-Za-z])(?=.*[0-9])[a-zA-Z0-9@$!%*#?&]{8,}$"
        )
      ),
    });
    await registerSchema.validateAsync(req.body);
    
    const { name, email, password, role } = req.body;

    // Hash password & save to mongoDB
    const hash = await bcrypt.hash(password, 10);
    const newUser = new users({
      name,
      email,
      password: hash,
      role,
    });
    await newUser.save();

    const accessToken = jwt.sign(
      { name, email, role },
      process.env.JWT_SECRET,
      {
        expiresIn: "24h",
      }
    );

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