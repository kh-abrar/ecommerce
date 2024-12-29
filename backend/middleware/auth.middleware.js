import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async(req, res, next) =>{
    try {
        const accessToken = req.cookies.accessToken;
        if(!accessToken) return res.status(401).json({message: "Unauthorized"});
        try {
            const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
            const user = await User.findById(decoded.userId).select("-password");
            if(!user) return res.status(401).json({message: "User not found"});
    
            req.user = user;
            next();
        } catch (error) {
            if(error.name==="TokenExpiredError") return res.status(401).json({message: "Access token expired"});

            throw error;
        }

    } catch (error) {
        console.log('Error in protectRoute middleware', error.message);
        res.status(401).json({message:"Unauthorized- Invalid access token"});
    }
}

export const adminRoute = (req, res, next) => {
    if (req.user?.role === "admin") { // Optional chaining for safer access
        return next();
    }
    return res.status(403).json({ message: "Forbidden: Admin access required" });
};
