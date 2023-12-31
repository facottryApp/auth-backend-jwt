import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, "Provide Email"],
      unique: [true, "Email already exists"],
    },

    password: {
      type: String,
      required: [true, "Provide password"],
    },

    name: {
      type: String,
      default: "",
    },

    mobile: {
      type: Number,
      default: "",
    },

    address: {
      type: String,
      default: "",
    },
  },
  { timestamps: true }
);

export default mongoose.model.users || mongoose.model("user", userSchema);