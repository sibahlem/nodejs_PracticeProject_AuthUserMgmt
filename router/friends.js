const express = require('express');

const router = express.Router();

let friends = {
    "johnsmith@gamil.com": {"firstName": "John","lastName": "Doe","DOB":"22-12-1990"},
    "annasmith@gamil.com":{"firstName": "Anna","lastName": "smith","DOB":"02-07-1983"},
    "peterjones@gamil.com":{"firstName": "Peter","lastName": "Jones","DOB":"21-03-1989"}
};


// GET request: Retrieve all friends (get all the user information using JSON string.)
router.get("/",(req,res)=>{
  res.send(JSON.stringify(friends,null,4));
});

// GET by specific ID request: Retrieve a single friend with email ID (code  to view the user based on email but without using filter method.)
router.get('/:email',function (req, res) {
  const email = req.params.email;
  res.send(friends[email])
  });


// POST request: Add a new friend (Code to add the new user to the JSON/dictionary.And also update the codes in the places mentioned.)
router.post("/",function (req,res){
  if (req.body.email){
      friends[req.body.email] = {
          "firstName":req.body.firstName,
          "lastName":req.body.lastName,
          "DOB":req.body.DOB
          }
  }
res.send("The user" + (' ')+ (req.body.firstName) + " Has been added!");
});


// PUT request: Update the details of a friend with email id. (Code to modify the friend details.And also add the codes in the places mentioned.)
router.put("/:email", function (req, res) {
  const email = req.params.email;
  let friend = friends[email]
  if (friend) { //Check is friend exists
      let DOB = req.body.DOB;
      let firstName = req.body.firstName;
      let lastName = req.body.lastName;

      //if DOB the DOB has been changed, update the DOB. (Code to modify the friend details.And also add the codes in the places mentioned.)
      if(DOB) {
          friend["DOB"] = DOB
      }
      if(firstName) {
        friend["firstName"] = firstName
      }
      if(lastName) {
          friend["lastName"] = lastName
      }
  }
  else{
      res.send("Unable to find friend!");
  }
});


// DELETE request: Delete a friend by email id. (Code to delete the friend information based on the email.)
router.delete("/:email", (req, res) => {
  const email = req.params.email;
  if (email){
      delete friends[email]
  }
  res.send(`Friend with the email  ${email} deleted.`);
});

module.exports=router;
