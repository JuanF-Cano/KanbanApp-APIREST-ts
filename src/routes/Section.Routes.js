import { Router } from "express";
import { getSections, getSectionsTasks, createSection, deleteSection, updateSection } from "../controllers/Section.Controller.js";
import { authenticateToken } from "../middleware/jwt.js";

const sectionRouter = Router();

sectionRouter.get("/sections/:id_users", authenticateToken, getSections); 

sectionRouter.get("/sections/tasks/:id_users", authenticateToken, getSectionsTasks);

sectionRouter.post("/section", authenticateToken, createSection);

sectionRouter.delete("/section/:id_section", authenticateToken, deleteSection);

sectionRouter.put("/section/:id_section", authenticateToken, updateSection);

export default sectionRouter;