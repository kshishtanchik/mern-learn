const {Router}=require('express')
const bcrypt=require('bcryptjs')
const jwt=require('jsonwebtoken')
const config=require('config')
const {check,validationResult}=require('express-validator')
const User =require('../models/User')
const router=Router()

// api/auth/register
router.post(
    '/register',
    [
        check('email','Некорректный email').isEmail(),
        check('password','Длина пароля должна быть 6 символоав').isLength({min:6})
    ],
    async (req,res)=>{
    try {
        console.log('Содержимое запроса:',req.body)
        const errors=validationResult(req)
        if(!errors.isEmpty()){
            return res.status(400).json({
                errors:errors.array(),
                message:'Некорректные данные'
            })
        }

        const{email,password}=req.body
        const candidate= await User.findOne({email})
        if(candidate){
            res.status(400).json({message:'Данный пользователь существует'})
        }
        const hashedPass=await bcrypt.hash(password,12)
        const user = new User({email,password:hashedPass})
        await user.save();
        res.status(201).json({message:'Пользователь создан'})

    }catch (e) {
        res.status(500).json({message:'Ошибка при регистрации'+e.message})
    }
})

// api/aurh/login
router.post(
    '/login',
    [
        check('email','Некорректный email').normalizeEmail().isEmail(),
        check('password','Введите пароль').exists()
    ],
    async (req,res)=>{
        try {
            const errors=validationResult(req)
            if(!errors.isEmpty()){
                return res.status(400).json({
                    errors:errors.array(),
                    message:'Некорректные данные при входе в систему'
                })
            }
            const{email,password}=req.body
            const user= await User.findOne({email})
            if(!user){
                return res.status(400).json({message:'Не верный логин или пароль'})
            }

            const isValidPass=await bcrypt.compare(password,user.password)
            if(!isValidPass){
                return res.status(400).json({message:'Не верный логин или пароль'})
            }
            const token=jwt.sign(
                {userId:user.id},
                config.get('jwtSecret'),
                {expiresIn:'1h'}
            )

            res.json({token,userId:user.id})


        }catch (e) {
            res.status(500).json({message:'Ошибка при входе:'+ e.message})
        }
})

module.exports=router