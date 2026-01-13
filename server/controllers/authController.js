//controllers are used for new users can store their details easily through the controllers

import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodel.js';



export const register=async(req,res)=>{
    const {name,email,password}=req.body;
    //checks emails user are entered or not
    if(!name||!email||!password){
        return res.json({success:false,message:'missing details'});
    }
    try{

        const existingUser=await userModel.findOne({email})
        
//checks if user exist or not
        if(existingUser){
            return res.json({success:false,message:'already exits'});
        }
//this is for password encrypt using bcrypt
        const hashedPassword=await bcrypt.hash(password,10);
        //we are create a user using userModel in const user
        const user=new userModel({name,email,password:hashedPassword});
        await user.save();


        //generate token using jwt cookies for authentication 
        const token=jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});


        //send the token to user to get response using cookie
        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV==='production',
            sameSite:process.env.NODE_ENV==='production'?'none':'strict',
            maxAge:7*24*60*60*1000
        
        })
          //register successful
        return res.json({success:true})



    }
    //if any error occurs this message will be highlighted
    catch(error){
        res.json({success:false,message:error.message})
    }
}



           //Login functionality

export const login=async(req,res)=>{

    //taking email and password
    const{email,password}=req.body;

    //check if mail or pass word wrong

    if(!email||!password){
        return res.json({success:false,message:'email and password require'});
    }
    try{
        const user=await userModel.findOne({email});
        //checks user 
        if(!user){
            return res.json({success:false,message:'invalid email'
            })

        }

        //get the password and compare

        const isMatch= await bcrypt.compare(password,user.password)

        //checks the password correct or not
        if(!isMatch){
            return res.json({success:false,message:'invalid password'});
        }
         //generate token using jwt cookies for authentication 
        const token=jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});


        //send the token to user to get response using cookie
        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV==='production',
            sameSite:process.env.NODE_ENV==='production'?'none':'strict',
            maxAge:7*24*60*60*1000
        
        });
//login successful
        return res.json({success:true});


    }
    //check try throws error to catch
    catch(error){
        return res.json({success:false,message: error.message});
    }



}


//😊logout functionality
export const logout=async(req,res)=>{
    

    try{
        //in this try section cookie will clear 
        res.clearCookie('token',{
            httpOnly:true,
            secure:process.env.NODE_ENV==='production',
            sameSite:process.env.NODE_ENV==='production'?'none':'strict',
            maxAge:7*24*60*60*1000

        });

        //logout successful
        return res.json({success:true,message:'logout successful'
        });


    }
    catch(error){
        return res.json({success:false,message:error.message});


    }
}