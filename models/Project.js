import mongoose from "mongoose";

const projectSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, "Title is required"],
      trim: true,
      maxlength: [120, "Title must be under 120 characters"],
    },
    description: {
      type: String,
      required: [true, "Description is required"],
      trim: true,
      maxlength: [2000, "Description must be under 2000 characters"],
    },
    liveUrl: {
      type: String,
      required: [true, "Live URL is required"],
      trim: true,
      match: [/^https?:\/\/.+/i, "Live URL must be a valid http(s) link"],
    },
    image: {
      type: String,
      trim: true,
      default: "",
      maxlength: [500, "Preview image URL is too long"],
    },
  },
  { timestamps: true }
);

export default mongoose.model("Project", projectSchema);