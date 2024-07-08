const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const authMiddleWare = (req, res, next) => {
  const authorizationHeader = req.headers.authorization;
  if (!authorizationHeader || !authorizationHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      status: "ERR",
      message: "Unauthorized access",
    });
  }
  const token = authorizationHeader.split(" ")[1];
  jwt.verify(token, process.env.ACCESS_TOKEN, function (err, user) {
    if (err) {
      return res.status(404).json({
        message: `The authemtication ${err}`,
        status: "ERR",
      });
    }
    if (user?.isAdmin) {
      next();
    } else {
      return res.status(404).json({
        message: "The authemtication",
        status: "ERR",
      });
    }
  });
};

const authUserMiddleWare = (req, res, next) => {
  const authorizationHeader = req.headers.authorization;
  if (!authorizationHeader || !authorizationHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Unauthorized access",
      status: "ERR",
    });
  }
  const token = authorizationHeader.split(" ")[1];
  const userId = req.params.id;
  jwt.verify(token, process.env.ACCESS_TOKEN, function (err, user) {
    if (err) {
      return res.status(200).json({
        message: `The authemtication: ${err}`,
        status: "ERR",
      });
    }
    if (user?.isAdmin || user?.id === userId) {
      next();
    } else {
      return res.status(404).json({
        message: `The authemtication: ${err}`,
        status: "ERR",
      });
    }
  });
};

module.exports = {
  authMiddleWare,
  authUserMiddleWare,
};
