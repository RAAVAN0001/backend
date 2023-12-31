import { ApiError } from "../utils/ApiError";
import { asyncHandler } from "../utils/asynhandler";
import { Jwt } from "jsonwebtoken";
import { User } from "../models/user.model";


export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookie?.accessToken || req.header("Authorization")?.replace("Bearer ", "")

        if (!token) {
            throw new ApiError(401, "UNathorizez request")
        }

        const decodedToken = jwt.verifyJWT(token, process.env.ACCESS_TOKEN_SECRET)

        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")

        if (!user) {
            //descuss about frontend
            throw new ApiError(401, "invalid access token")
        }

        req.user = user
        next()
    } catch (error) {
        throw new ApiError(401, error?.message || "invalid access token")
    }

})