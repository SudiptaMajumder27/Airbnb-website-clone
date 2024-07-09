const { ObjectId } = require('mongodb');
// const bcrypt = require('bcrypt');
const Listing = require("./models/listing");
const ExpressError = require("./utils/ExpressError.js");
const { listingSchema, reviewSchema } = require("./schema.js");
const Review = require("./models/review");
const bcrypt = require("bcryptjs");




module.exports.isLoggedIn = (req, res , next)=>{
  console.log(req.path, "..", req.originalUrl);
    if(!req.isAuthenticated()) {
      req.session.redirectUrl = req.originalUrl;
        req.flash("error", "you must be logged in to create listing !");
        return res.redirect("/login");
      }
      next();
};

module.exports.saveRedirectUrl = (req, res, next) =>{
  if(req.session.redirectUrl) {
    res.locals.redirectUrl = req.session.redirectUrl;
  }
  next();
};

module.exports.isOwner = async (req, res, next) => {
  try {
      let { id } = req.params;
      let listing = await Listing.findById(id);

      if (!listing) {
          req.flash("error", "Listing not found");
          return res.redirect('/listings');
      }

      if (!listing.owner && !res.locals.currUser) {
          req.flash("error", "You are not the owner!");
          return res.redirect(`/listings/${id}`);
      }

      // Verify the password (assuming res.locals.currUser.password contains the hashed password)
      const passwordMatch = await bcrypt.compare(req.body.password, res.locals.currUser.password);

      if (listing.owner.username === res.locals.currUser.username && passwordMatch) {
          listing.owner._id = ObjectId(res.locals.currUser._id);
          await listing.save();
      }

      if (!listing.owner._id.equals(ObjectId(res.locals.currUser._id))) {
          req.flash("error", "You are not the owner of this listing");
          return res.redirect(`/listings/${id}`);
      }

      next();
  } catch (error) {
      console.log(error);
      req.flash("error", "You are not the owner of this listing!");
      return res.redirect('/listings');
  }
};

module.exports.validateListing = (req, res, next) =>{
  let {error} =listingSchema.validate(req.body);
   if(error){
    let errMsg = error.details.map((el)=> el.message).join(",");
     throw new ExpressError(400, errMsg);
    }else{
    next();
   }
};

module.exports.validateReview = (req, res, next) =>{
  let {error} = reviewSchema.validate(req.body);
   if(error){
    let errMsg = error.details.map((el)=> el.message).join(",");
     throw new ExpressError(400, errMsg);
    }else{
    next();
   }
};

module.exports.isReviewAuthor = async (req,res,next) =>{
  let { id, reviewId } = req.params;
  let review = await Review.findById(reviewId);
  if(!review.author.equals(res.locals.currUser._id)) {
  req.flash("error", "You are not the owner of this listing ");
    return res.redirect(`/listings/${id}`);
  }
  next();
};
