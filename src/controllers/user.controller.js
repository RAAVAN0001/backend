import {asyncHandler} from '../utils/asynhandler.js'

const registerUser = asyncHandler(async (req,res)=>{
    res.status(200).json({
        message:"hey"
    })
})


export {registerUser}