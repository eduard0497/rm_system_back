require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const knex = require("knex");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const app = express();
app.use(express.json());
app.use(cookieParser());
const SUBSCRIPTION_PRICE_IN_CENTS = 2000;

//
// CORS CONFIG
//
const corsOptions = {
  origin: [process.env.FRONT_DOMAIN],
  credentials: true,
};
app.use(cors(corsOptions));

//
// NODEMAILER CONFIG
//
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.DUMMY_GMAIL,
    pass: process.env.DUMMY_GMAIL_PASSWORD,
  },
});

//
// DATABASE CONFIG
//
const configDB = () => {
  const isDevMode = process.env.IS_DEV_MODE === "1";

  const baseConfig = {
    client: "pg",
    connection: {
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      port: process.env.DB_PORT,
      database: process.env.DB_NAME,
    },
  };

  if (!isDevMode) {
    baseConfig.connection.ssl = { rejectUnauthorized: false };
  }

  return baseConfig;
};
const db = knex(configDB());
const T_OWNERS = "owners";
const T_RESTAURANTS = "restaurants";
const T_TRANSACTIONS = "transactions";
const T_EMPLOYEES = "employees";
const T_EMPL_REST_ACCESS = "employee_restaurant_accesses";
const T_CATEGORIES = "categories";
const T_MENU_ITEMS = "menu_items";
const T_SERVER_SENT_EMAILS = "server_sent_emails";

//
// STRIPE CONFIG
//
const STRIPE_SECRET_KEY =
  process.env.IS_DEV_MODE === "1"
    ? process.env.STRIPE_TEST_SECRET_KEY
    : process.env.STRIPE_PRODUCTION_SECRET_KEY;
const stripe = require("stripe")(STRIPE_SECRET_KEY);

//
// ACCOUNT TYPES
//
const ACCOUNT_TYPE_OWNER = "owner";
const ACCOUNT_TYPE_EMPLOYEE = "employee";

//
// MIDDLEWARES
//
const verifyToken = (req, res, next) => {
  try {
    // const { token } = req.body;
    const { token } = req.cookies;
    if (!token) {
      return res.json({
        status: 0,
        kick_out: true,
        msg: "Unauthorized User - No token provided",
      });
    }
    let decodedToken;
    try {
      decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
    } catch (error) {
      return res.json({
        status: 0,
        kick_out: true,
        msg: "Unauthorized User - Token has expired",
      });
    }
    req.body.decoded_user_id = decodedToken.user_id;
    req.body.decoded_user_email_address = decodedToken.user_email_address;
    req.body.decoded_account_type = decodedToken.account_type;
    next();
  } catch (e) {
    console.log(e);
    res.json({
      status: 0,
      kick_out: true,
      msg: "Unauthorized!!!",
    });
  }
};

//
// Routes
//
app.post("/register-owner", async (req, res) => {
  const {
    owner_first_name,
    owner_last_name,
    owner_email_address,
    owner_password,
  } = req.body;

  let hashedPassword = await bcrypt.hashSync(owner_password, 10);

  db(T_OWNERS)
    .returning("*")
    .insert({
      owner_first_name,
      owner_last_name,
      owner_email_address,
      owner_email_verified: false,
      owner_password: hashedPassword,
      date_registered: new Date().toISOString(),
    })
    .then((data) => {
      if (data.length < 1) {
        res.json({
          status: 0,
          msg: "Unable to register owner",
        });
      } else {
        let {
          owner_id,
          owner_first_name,
          owner_last_name,
          owner_email_address,
        } = data[0];
        let token = jwt.sign(
          { owner_id, owner_email_address },
          process.env.JWT_SECRET_KEY
        );
        let email_text = generateEmailForOwnerVerification(
          owner_first_name,
          owner_last_name,
          token
        );
        let mailOpts = mailOptions(
          owner_email_address,
          "Please verify your email address",
          email_text
        );
        let noteToAdd = "Owner needs to verify the email address";
        sendEmail(mailOpts, noteToAdd).then((sent) => {
          if (sent) {
            res.json({
              status: 1,
              msg: "An email has been sent to you",
            });
          } else {
            res.json({
              status: 1,
              msg: "The registration was successful, but was unable to send email",
            });
          }
        });
      }
    })
    .catch((e) => {
      if ((e.code = "23505")) {
        res.json({
          status: 0,
          msg: "Email address is already in use",
        });
      } else {
        res.json({
          status: 0,
          msg: "Internal server error occured",
        });
      }
    });
});

app.post("/verify-owner-email", (req, res) => {
  const { token } = req.body;

  if (!token) {
    res.json({
      status: 0,
      msg: "No token was provided",
    });
    return;
  }
  let decodedToken;
  try {
    decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
  } catch (error) {
    console.log(error);
    res.json({
      status: 0,
      msg: "Invalid token",
    });
    return;
  }
  let { owner_id, owner_email_address } = decodedToken;

  db(T_OWNERS)
    .select("*")
    .where({
      owner_id,
      owner_email_address,
    })
    .then((data) => {
      if (data.length != 1) {
        res.json({
          status: 0,
          msg: "Unable to authenticate the token",
        });
        return;
      }
      if (data[0].owner_email_verified) {
        res.json({
          status: 0,
          msg: "The email address have already been verified",
        });
        return;
      }
      db(T_OWNERS)
        .returning("*")
        .update({
          owner_email_verified: true,
        })
        .where({
          owner_id,
          owner_email_address,
        })
        .then((data) => {
          if (!data.length) {
            res.json({
              status: 0,
              msg: "Unable to verify the email address",
            });
          } else {
            res.json({
              status: 1,
              msg: "The emaill address have been verified successfully",
            });
          }
        })
        .catch((e) => {
          console.log(e);
          res.json({
            status: 0,
            msg: "Internal server error",
          });
        });
    })
    .catch((e) => {
      console.log(e);
      res.json({
        status: 0,
        msg: "Internal server error",
      });
    });
});

app.post("/owner-login", (req, res) => {
  const { owner_email_address, owner_password } = req.body;

  db(T_OWNERS)
    .select("*")
    .where({
      owner_email_address,
    })
    .then((data) => {
      if (data.length != 1) {
        res.json({
          status: 0,
          msg: "Invalid Email/Password",
        });
        return;
      }
      if (!bcrypt.compareSync(owner_password, data[0].owner_password)) {
        res.json({
          status: 0,
          msg: "Invalid Email/Password",
        });
        return;
      }
      if (!data[0].owner_email_verified) {
        res.json({
          status: 0,
          msg: "Verify your email address to continue",
        });
        return;
      }
      let token = jwt.sign(
        {
          user_id: data[0].owner_id,
          user_email_address: data[0].owner_email_address,
          account_type: ACCOUNT_TYPE_OWNER,

          // expiration: setExpDateForToken(2),
        },
        process.env.JWT_SECRET_KEY
      );
      res.json({
        status: 1,
        token,
      });
    })
    .catch((e) => {
      console.log(e);
      res.json({
        status: 0,
        msg: "Internal server error",
      });
    });
});

app.post("/validate-token", verifyToken, (req, res) => {
  const { decoded_user_id, decoded_account_type } = req.body;

  if (!decoded_user_id) {
    res.json({
      status: 0,
      no_decoded_user: true,
      msg: "Unable to verify the token",
    });
  } else {
    res.json({
      status: 1,
      account_type: decoded_account_type,
      msg: "Token has been validated successfully",
    });
  }
});

app.post("/get-restaurants", verifyToken, (req, res) => {
  const { decoded_user_id, decoded_account_type } = req.body;
  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      kick_out: true,
      msg: "Unauthorized user",
    });
  }
  db(T_RESTAURANTS)
    .select("*")
    .where({
      restaurant_owner_id: decoded_user_id,
    })
    .then((data) => {
      res.json({
        status: 1,
        restaurants: data,
      });
    })
    .catch((e) => {
      res.json({
        status: 0,
        msg: "Internal Server Error",
      });
    });
});

app
  .route("/register-restaurant")
  .all(verifyToken)
  .post((req, res) => {
    const {
      decoded_user_id,
      decoded_account_type,
      restaurant_name,
      restaurant_address_street,
      restaurant_address_unit,
      restaurant_address_city,
      restaurant_address_state,
      restaurant_address_zip,
      restaurant_phone_number,
      restaurant_fax_number,
      restaurant_email_address,
      restaurant_menu_note,
    } = req.body;

    if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
      return res.json({
        status: 0,
        msg: "Unauthorized user",
      });
    }

    db(T_RESTAURANTS)
      .returning("*")
      .insert({
        restaurant_owner_id: decoded_user_id,
        restaurant_name,
        restaurant_address_street,
        restaurant_address_unit,
        restaurant_address_city,
        restaurant_address_state,
        restaurant_address_zip,
        restaurant_phone_number,
        restaurant_fax_number,
        restaurant_email_address,
        restaurant_menu_note,
        restaurant_is_active: false,
      })
      .then((data) => {
        if (data.length != 1) {
          res.json({
            status: 0,
            msg: "Unable to add the restaurant",
          });
          return;
        }
        res.json({
          status: 1,
          restaurantAsObject: data[0],
        });
      })
      .catch((e) => {
        console.log(e);
        res.json({
          status: 0,
          msg: "Internal server error",
        });
      });
  })
  .put((req, res) => {
    const {
      decoded_user_id,
      decoded_account_type,
      restaurant_id,
      restaurant_name,
      restaurant_address_street,
      restaurant_address_unit,
      restaurant_address_city,
      restaurant_address_state,
      restaurant_address_zip,
      restaurant_phone_number,
      restaurant_fax_number,
      restaurant_email_address,
      restaurant_menu_note,
    } = req.body;

    if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
      return res.json({
        status: 0,
        msg: "Unauthorized user",
      });
    }

    db(T_RESTAURANTS)
      .returning("*")
      .update({
        restaurant_name,
        restaurant_address_street,
        restaurant_address_unit,
        restaurant_address_city,
        restaurant_address_state,
        restaurant_address_zip,
        restaurant_phone_number,
        restaurant_fax_number,
        restaurant_email_address,
        restaurant_menu_note,
        restaurant_is_active: false,
      })
      .where({
        restaurant_owner_id: decoded_user_id,
        restaurant_id,
      })
      .then((data) => {
        if (data.length != 1) {
          res.json({
            status: 0,
            msg: "Unable to update restaurant details",
          });
          return;
        }
        res.json({
          status: 1,
          restaurantAsObject: data[0],
        });
      })
      .catch((e) => {
        console.log(e);
        res.json({
          status: 0,
          msg: "Internal server error",
        });
      });
  });

app.post("/get-current-subscription-details", verifyToken, (req, res) => {
  const { decoded_user_id, decoded_account_type, restaurant_id } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unauthorized user",
    });
  }

  db(T_TRANSACTIONS)
    .whereNotNull("subscription_end_date")
    .where({
      restaurant_id,
    })
    .orderBy("subscription_end_date", "desc")
    .select("*")
    .limit(1)
    .then((data) => {
      res.json({
        status: 1,
        latestTransaction: data,
      });
    })
    .catch((e) => {
      console.log(e);
      res.json({
        status: 0,
        msg: "Internal server error",
      });
    });
});

app.post("/start-trial", verifyToken, async (req, res) => {
  const {
    decoded_user_id,
    decoded_account_type,
    decoded_user_email_address,
    restaurant_id,
  } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unauthorized user",
    });
  }

  try {
    const existingTransactions = await db(T_TRANSACTIONS)
      .select("*")
      .where({ restaurant_id });

    if (existingTransactions.length > 0) {
      return res.json({
        status: 0,
        msg: "Not eligible for trial",
      });
    }

    const newTransaction = await db(T_TRANSACTIONS).returning("*").insert({
      restaurant_id,
      subscription_end_date: generateDate30DaysFromNow(),
      transaction_timestamp: new Date().toISOString(),
    });

    if (newTransaction.length !== 1) {
      return res.json({
        status: 0,
        msg: "Unable to start the trial in server",
      });
    }

    const updatedRestaurant = await db(T_RESTAURANTS)
      .returning("*")
      .update({
        restaurant_is_active: true,
      })
      .where({
        restaurant_owner_id: decoded_user_id,
        restaurant_id,
      });

    if (updatedRestaurant.length !== 1) {
      return res.json({
        status: 0,
        msg: "The transaction table has been updated, but unable to activate the restaurant",
      });
    }

    let email_text =
      "Thank you for starting the trial!\nWe hope you will enjoy the system";
    let mailOpts = mailOptions(
      decoded_user_email_address,
      `Notification for ${updatedRestaurant[0].restaurant_name}`,
      email_text
    );
    let noteToAdd = `Notified that trial had been started for ${updatedRestaurant[0].restaurant_name}`;
    sendEmail(mailOpts, noteToAdd).then(() => {
      res.json({
        status: 1,
        latestTransaction: newTransaction,
        updatedRestaurantDetails: updatedRestaurant[0],
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 0,
      msg: "Internal server error",
    });
  }
});

app.post("/create-checkout-session", verifyToken, async (req, res) => {
  const { decoded_user_id, decoded_account_type, restaurant_id } = req.body;
  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unauthorized user",
    });
  }

  try {
    const insertedTransaction = await db(T_TRANSACTIONS).returning("*").insert({
      restaurant_id,
      subscription_end_date: null,
      transaction_timestamp: new Date().toISOString(),
    });

    if (insertedTransaction.length !== 1) {
      return res.json({
        status: 0,
        msg: "Unable to start a transaction",
      });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: "Monthly Subscription",
            },
            unit_amount: SUBSCRIPTION_PRICE_IN_CENTS,
          },
          quantity: 1,
        },
      ],
      success_url: `${process.env.FRONT_DOMAIN}/payment-result?session_id={CHECKOUT_SESSION_ID}&transaction_id=${insertedTransaction[0].id}&restaurant_id=${insertedTransaction[0].restaurant_id}`,
      cancel_url: `${process.env.FRONT_DOMAIN}/dashboard`,
    });

    res.json({
      status: 1,
      session_url: session.url,
    });
  } catch (error) {
    console.error("Error creating checkout session:", error);
    res.json({
      status: 0,
      msg: "Error creating the checkout session",
    });
  }
});

app.post("/process-payment", verifyToken, async (req, res) => {
  const {
    decoded_user_id,
    decoded_account_type,
    decoded_user_email_address,
    session_id,
    transaction_id,
    restaurant_id,
  } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unauthorized user",
    });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);

    const paymentIntent = await stripe.paymentIntents.retrieve(
      session.payment_intent
    );
    const paymentMethod = await stripe.paymentMethods.retrieve(
      paymentIntent.payment_method
    );

    const card_brand = paymentMethod.card.brand; //visa
    const card_exp_month = paymentMethod.card.exp_month;
    const card_exp_year = paymentMethod.card.exp_year;
    const card_last_four = paymentMethod.card.last4;

    const payment_intent = session.payment_intent;
    const amount_total = session.amount_total; // int
    const postal_code = session.customer_details.address.postal_code; // STRING
    const email = session.customer_details.email;
    const name = session.customer_details.name;
    const created = session.created; // large int when session started
    const payment_status = session.payment_status; // payment status
    const status = session.status; //session status

    let checkedTransaction = await db(T_TRANSACTIONS)
      .select("*")
      .where({
        id: transaction_id,
        restaurant_id,
      })
      .whereNotNull("session_id");

    if (checkedTransaction.length !== 0) {
      return res.json({
        status: 0,
        msg: "Either the transaction had already been verified, or it does not exist",
      });
    }

    let latestTransaction = await db(T_TRANSACTIONS)
      .whereNotNull("subscription_end_date")
      .andWhere({
        restaurant_id,
      })
      .orderBy("subscription_end_date", "desc")
      .select("*")
      .limit(1);

    if (latestTransaction.length !== 1) {
      return res.json({
        status: 0,
        msg: "Error retrieving latest subscription end date",
      });
    }
    let latestSubscriptionEndDate = latestTransaction[0].subscription_end_date;

    let newSubscriptionEndDate = generateNewDateFromEndDate(
      latestSubscriptionEndDate
    );

    let updatedTransaction = await db(T_TRANSACTIONS)
      .returning("*")
      .update({
        session_id,
        session_status: status,
        amount_total,
        payment_status,
        provided_email: email,
        provided_name: name,
        payment_intent,
        card_brand,
        card_exp_month,
        card_exp_year,
        card_last_four,
        subscription_end_date: newSubscriptionEndDate,
      })
      .where({
        id: transaction_id,
        restaurant_id,
      });

    if (updatedTransaction.length !== 1) {
      return res.json({
        status: 0,
        msg: "Unable to update the transaction",
      });
    }

    const activatedRestaurant = await db(T_RESTAURANTS)
      .returning("*")
      .update({
        restaurant_is_active: true,
      })
      .where({
        restaurant_id,
        restaurant_owner_id: decoded_user_id,
      });

    if (activatedRestaurant.length !== 1) {
      res.json({
        status: 0,
        msg: "Transaction went through, however an error occured",
      });
    }

    let email_text =
      "Thank you for subscribing!\nWe hope you will enjoy the system";
    let mailOpts = mailOptions(
      decoded_user_email_address,
      `Notification for ${activatedRestaurant[0].restaurant_name}`,
      email_text
    );
    let noteToAdd = `Thanked for payment for ${activatedRestaurant[0].restaurant_name}`;
    sendEmail(mailOpts, noteToAdd).then(() => {
      res.json({
        status: 1,
        msg: "Thank you for your payment!\nAn email confirmation has been sent to you\nRedirecting to dashboard...",
      });
    });
  } catch (error) {
    console.log("Error");
    console.log(error);
    res.json({
      status: 0,
      msg: "Internal server error",
    });
  }
});

app.post("/get-payment-activity", verifyToken, async (req, res) => {
  const { decoded_user_id, decoded_account_type } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unauthorized user",
    });
  }

  const payments = await db(T_RESTAURANTS)
    .join(
      T_TRANSACTIONS,
      `${T_RESTAURANTS}.restaurant_id`,
      `${T_TRANSACTIONS}.restaurant_id`
    )
    .select(
      `${T_RESTAURANTS}.restaurant_name`,
      `${T_TRANSACTIONS}.id as transaction_id`,
      `${T_TRANSACTIONS}.amount_total`,
      `${T_TRANSACTIONS}.payment_status`,
      `${T_TRANSACTIONS}.provided_email`,
      `${T_TRANSACTIONS}.provided_name`,
      `${T_TRANSACTIONS}.card_brand`,
      `${T_TRANSACTIONS}.card_exp_month`,
      `${T_TRANSACTIONS}.card_exp_year`,
      `${T_TRANSACTIONS}.card_last_four`,
      `${T_TRANSACTIONS}.subscription_end_date`,
      `${T_TRANSACTIONS}.transaction_timestamp`
    )
    .where(`${T_RESTAURANTS}.restaurant_owner_id`, decoded_user_id)
    .whereNotNull(`${T_TRANSACTIONS}.session_id`)
    .orderBy(`${T_TRANSACTIONS}.id`, `desc`)
    .catch((e) => {
      console.log(e);
      return res.json({
        status: 0,
        msg: "Internal server error",
      });
    });

  res.json({
    status: 1,
    payments,
  });
});

app.post("/add-employee", verifyToken, async (req, res) => {
  const {
    decoded_user_id,
    decoded_account_type,
    employee_first_name,
    employee_last_name,
    employee_email_address,
    employee_username,
  } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unauthorized user",
    });
  }

  try {
    let addedEmployee = await db(T_EMPLOYEES).returning("*").insert({
      restaurant_owner_id: decoded_user_id,
      employee_first_name,
      employee_last_name,
      employee_email_address,
      employee_username,
      employee_is_active: true,
    });

    if (addedEmployee.length !== 1) {
      return res.json({
        status: 0,
        msg: "Unable to add employee",
      });
    }

    res.json({
      status: 1,
      addedEmployee,
    });
  } catch (e) {
    if (e.code === "23505") {
      return res.json({
        status: 0,
        msg: "Such username already exists",
      });
    }
    return res.json({
      status: 0,
      msg: "Server Error",
    });
  }
});

app.post("/get-employees", verifyToken, async (req, res) => {
  const { decoded_user_id, decoded_account_type } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unauthorized user",
    });
  }

  const employees = await db(T_EMPLOYEES)
    .select("*")
    .where({
      restaurant_owner_id: decoded_user_id,
    })
    .orderBy("employee_id", "asc")
    .catch((e) => {
      console.log(e);
      return res.json({
        status: 0,
        msg: "Internal server error",
      });
    });

  res.json({
    status: 1,
    employees,
  });
});

app.post("/email-login-instructions", verifyToken, async (req, res) => {
  const { decoded_user_id, decoded_account_type, employee_id } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unauthorized user",
    });
  }

  try {
    let employeeDetails = await db(T_EMPLOYEES)
      .join(
        T_OWNERS,
        `${T_OWNERS}.owner_id`,
        "=",
        `${T_EMPLOYEES}.restaurant_owner_id`
      )
      .select(
        `${T_EMPLOYEES}.employee_id`,
        `${T_EMPLOYEES}.employee_first_name`,
        `${T_EMPLOYEES}.employee_last_name`,
        `${T_EMPLOYEES}.employee_email_address`,
        `${T_EMPLOYEES}.employee_username`,
        `${T_OWNERS}.owner_id`,
        `${T_OWNERS}.owner_first_name`,
        `${T_OWNERS}.owner_last_name`
      )
      .where(`${T_EMPLOYEES}.employee_id`, employee_id)
      .where(`${T_OWNERS}.owner_id`, decoded_user_id);

    if (employeeDetails.length !== 1) {
      return res.json({
        status: 0,
        msg: "Unable to send email to the employee",
      });
    }

    let email_text = generateEmployeeLoginInstructionText(
      employeeDetails[0].employee_id,
      employeeDetails[0].employee_first_name,
      employeeDetails[0].employee_last_name,
      employeeDetails[0].employee_username,
      employeeDetails[0].owner_id,
      employeeDetails[0].owner_first_name,
      employeeDetails[0].owner_last_name
    );

    let mailOpts = mailOptions(
      employeeDetails[0].employee_email_address,
      `You have been registered as employee`,
      email_text
    );

    let noteToAdd = `${employeeDetails[0].owner_first_name} ${employeeDetails[0].owner_last_name} (id - ${employeeDetails[0].owner_id}) tried to send login instructions to ${employeeDetails[0].employee_first_name} ${employeeDetails[0].employee_last_name} (id - ${employeeDetails[0].employee_id})`;
    sendEmail(mailOpts, noteToAdd)
      .then((sent) => {
        if (sent) {
          res.json({
            status: 1,
            msg: `Login instructions have been sent to ${employeeDetails[0].employee_first_name}`,
          });
        } else {
          res.json({
            status: 0,
            msg: "Unable to send the email instructions",
          });
        }
      })
      .catch((error) => {
        console.error("Error sending email:", error);
        res.json({
          status: 0,
          msg: "An error occurred while sending the email instructions",
        });
      });
  } catch (error) {
    console.log("Error");
    console.log(e);
    res.json({
      status: 0,
      msg: "Internal server error",
    });
  }
});

app.post("/edit-employee-details", verifyToken, async (req, res) => {
  const {
    decoded_user_id,
    decoded_account_type,
    employee_id,
    employee_first_name,
    employee_last_name,
    employee_email_address,
    employee_is_active,
  } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unauthorized user",
    });
  }

  try {
    let updatedEmployee = await db(T_EMPLOYEES)
      .returning("*")
      .update({
        employee_first_name,
        employee_last_name,
        employee_email_address,
        employee_is_active,
      })
      .where({
        restaurant_owner_id: decoded_user_id,
        employee_id,
      });

    if (updatedEmployee.length !== 1) {
      return res.json({
        status: 0,
        msg: "Unable to update employee details",
      });
    }

    const employees = await db(T_EMPLOYEES)
      .select("*")
      .where({
        restaurant_owner_id: decoded_user_id,
      })
      .orderBy("employee_id", "asc");

    res.json({
      status: 1,
      employees,
    });
  } catch (error) {
    console.log("Error");
    console.log(error);
  }
});

app.post("/get-restaurant-employee-accesses", verifyToken, async (req, res) => {
  const { decoded_user_id, decoded_account_type, restaurant_id } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unathorized to access the endpoint",
    });
  }

  try {
    const employeesWithAccessIDs = await db(`${T_EMPLOYEES} as e`)
      .leftJoin(`${T_EMPL_REST_ACCESS} as era`, function () {
        this.on("e.employee_id", "=", "era.employee_id").andOn(
          "era.restaurant_id",
          "=",
          restaurant_id
        );
      })
      .select(
        "e.employee_id",
        "e.employee_first_name",
        "e.employee_last_name",
        "e.employee_username",
        "era.id as employee_access_id"
      )
      .where("e.restaurant_owner_id", decoded_user_id)
      .orderBy("e.employee_id", "asc");

    res.json({
      status: 1,
      employeesWithAccessIDs,
    });
  } catch (error) {
    console.log("Error");
    console.log(error);
    res.json({
      status: 0,
      msg: "Internal Server Error",
    });
  }
});

app.post("/give-access-to-employee", verifyToken, async (req, res) => {
  const { decoded_user_id, decoded_account_type, restaurant_id, employee_id } =
    req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unathorized to access the endpoint",
    });
  }

  try {
    const addedAccess = await db(T_EMPL_REST_ACCESS).returning("*").insert({
      employee_id,
      restaurant_id,
      has_access: true,
    });

    if (addedAccess.length !== 1) {
      return res.json({
        status: 0,
        msg: "Error occured while giving access to the employee",
      });
    }

    res.json({
      status: 1,
      addedAccess,
    });
  } catch (error) {
    console.log("Error");
    console.log(error);
    res.json({
      status: 0,
      msg: "Internal Server Error",
    });
  }
});

app.post("/revoke-employee-access", verifyToken, async (req, res) => {
  const { decoded_user_id, decoded_account_type, access_id } = req.body;

  if (decoded_account_type !== ACCOUNT_TYPE_OWNER) {
    return res.json({
      status: 0,
      msg: "Unathorized to access the endpoint",
    });
  }

  try {
    const revokedAccess = await db(T_EMPL_REST_ACCESS)
      .returning("*")
      .del()
      .where({
        id: access_id,
      });

    if (revokedAccess.length !== 1) {
      return res.json({
        status: 0,
        msg: "Error occured while revoking access of the employee",
      });
    }

    res.json({
      status: 1,
      revokedAccess,
    });
  } catch (error) {
    console.log("Error");
    console.log(error);
    res.json({
      status: 0,
      msg: "Internal Server Error",
    });
  }
});

app.post("/search-employee-username", async (req, res) => {
  const { token, employee_username } = req.body;

  let decodedToken;
  try {
    decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
  } catch (error) {
    return res.json({
      status: 0,
      msg: "Invalid token has been provided",
    });
  }

  let employee_id = decodedToken.employee_id;
  let restaurant_owner_id = decodedToken.owner_id;
  let account_type = decodedToken.account_type;

  if (account_type !== ACCOUNT_TYPE_EMPLOYEE) {
    return res.json({
      status: 0,
      msg: "Unable to verify account type",
    });
  }

  let employeeFromDB = await db(T_EMPLOYEES).select("*").where({
    employee_id,
    restaurant_owner_id,
    employee_username,
  });

  if (employeeFromDB.length !== 1) {
    return res.json({
      status: 0,
      msg: "Invalid credentials",
    });
  }

  if (!employeeFromDB[0].employee_password) {
    res.json({
      status: 1,
      password_exists: false,
    });
  } else {
    res.json({
      status: 1,
      password_exists: true,
    });
  }
});

app.post("/employee-set-password", async (req, res) => {
  const { token, employee_username, employee_password } = req.body;

  let decodedToken;
  try {
    decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
  } catch (error) {
    return res.json({
      status: 0,
      msg: "Invalid token has been provided",
    });
  }

  let employee_id = decodedToken.employee_id;
  let restaurant_owner_id = decodedToken.owner_id;
  let account_type = decodedToken.account_type;

  if (account_type !== ACCOUNT_TYPE_EMPLOYEE) {
    return res.json({
      status: 0,
      msg: "Unable to verify account type",
    });
  }

  let hashedPassword = await bcrypt.hashSync(employee_password, 10);

  let updatedEmployeePassword = await db(T_EMPLOYEES)
    .returning("*")
    .update({
      employee_password: hashedPassword,
    })
    .where({
      employee_id,
      restaurant_owner_id,
      employee_username,
    });

  if (updatedEmployeePassword.length !== 1) {
    return res.json({
      status: 0,
      msg: "Unable to update employee password",
    });
  }

  let tokenForUser = jwt.sign(
    {
      user_id: updatedEmployeePassword[0].employee_id,
      user_email_address: updatedEmployeePassword[0].employee_email_address,
      account_type: ACCOUNT_TYPE_EMPLOYEE,

      // expiration: setExpDateForToken(2),
    },
    process.env.JWT_SECRET_KEY
  );

  res.json({
    status: 1,
    token: tokenForUser,
  });
});

app.post("/employee-login", async (req, res) => {
  const { token, employee_username, employee_password } = req.body;

  let decodedToken;
  try {
    decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
  } catch (error) {
    return res.json({
      status: 0,
      msg: "Invalid token has been provided",
    });
  }

  let employee_id = decodedToken.employee_id;
  let restaurant_owner_id = decodedToken.owner_id;
  let account_type = decodedToken.account_type;

  if (account_type !== ACCOUNT_TYPE_EMPLOYEE) {
    return res.json({
      status: 0,
      msg: "Unable to verify account type",
    });
  }

  let foundEmployee = await db(T_EMPLOYEES).select("*").where({
    employee_id,
    restaurant_owner_id,
    employee_username,
  });

  if (foundEmployee.length !== 1) {
    return res.json({
      status: 0,
      msg: "Unable to find employee info",
    });
  }

  if (
    !bcrypt.compareSync(employee_password, foundEmployee[0].employee_password)
  ) {
    res.json({
      status: 0,
      msg: "Invalid Credentials",
    });
    return;
  }

  let tokenForUser = jwt.sign(
    {
      user_id: foundEmployee[0].employee_id,
      user_email_address: foundEmployee[0].employee_email_address,
      account_type: ACCOUNT_TYPE_EMPLOYEE,

      // expiration: setExpDateForToken(2),
    },
    process.env.JWT_SECRET_KEY
  );

  res.json({
    status: 1,
    token: tokenForUser,
  });
});

// minchev es eli baner unem anelu, employee logini het kapvac,
// hly vor menak sugum em username ka te che
app.post("/get-restaurants-to-manage", verifyToken, async (req, res) => {
  const { decoded_user_id, decoded_user_email_address, decoded_account_type } =
    req.body;

  res.json(
    `UserID: ${decoded_user_id}, account: ${decoded_account_type}, email: ${decoded_user_email_address}`
  );
});

//
// LISTENING TO PORT
//
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`App is running on port ${PORT}`);
});

//
// HELPER FUNCTIONS
//
const mailOptions = (sendTo, subject, text) => {
  return {
    from: process.env.DUMMY_GMAIL,
    to: sendTo,
    subject: subject,
    text: text,
  };
};

const sendEmail = async (itemToMail, note) => {
  return new Promise((resolve, reject) => {
    transporter.sendMail(itemToMail, async (error, info) => {
      let currentDateForDB = formattedCurrentTimestamp();
      try {
        if (error) {
          console.error("Email sending error:", error);
          await db(T_SERVER_SENT_EMAILS).insert({
            sent_to: itemToMail.to,
            note,
            successful: false,
            smtp_response: error.message.trim().split("For more")[0],
            time_stamp: currentDateForDB,
          });
          resolve(false);
        } else {
          await db(T_SERVER_SENT_EMAILS).insert({
            sent_to: itemToMail.to,
            note,
            successful: true,
            smtp_response: info.response.trim(),
            time_stamp: currentDateForDB,
          });
          resolve(true);
        }
      } catch (dbError) {
        console.error("Database error:", dbError);
        reject(dbError);
      }
    });
  });
};

const generateEmailForOwnerVerification = (
  owner_first_name,
  owner_last_name,
  token
) => {
  return `Hello ${
    owner_first_name + " " + owner_last_name
  }!\n\nPlease click this link to verify your email address: ${
    process.env.FRONT_DOMAIN
  }/verify-email-address?token=${token}`;
};

const formattedCurrentTimestamp = () => {
  let date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
};

const generateDate30DaysFromNow = () => {
  const currentDate = new Date();
  currentDate.setDate(currentDate.getDate() + 30);

  const year = currentDate.getFullYear();
  const month = String(currentDate.getMonth() + 1).padStart(2, "0");
  const day = String(currentDate.getDate()).padStart(2, "0");

  return `${year}-${month}-${day}`;
};

const generateNewDateFromEndDate = (endDateString) => {
  const endDate = new Date(endDateString);
  const currentDate = new Date();

  if (endDate < currentDate) {
    return generateDate30DaysFromNow();
  } else {
    endDate.setDate(endDate.getDate() + 30);
    return endDate.toISOString().slice(0, 10);
  }
};

const generateEmployeeLoginInstructionText = (
  employee_id,
  employee_first_name,
  employee_last_name,
  employee_username,
  owner_id,
  owner_first_name,
  owner_last_name
) => {
  let token = jwt.sign(
    {
      employee_id,
      owner_id,
      account_type: ACCOUNT_TYPE_EMPLOYEE,
    },
    process.env.JWT_SECRET_KEY
  );

  let linkToInclude = `${process.env.FRONT_DOMAIN}/employee-login?token=${token}`;

  return `Hello ${employee_first_name} ${employee_last_name}!\nYour employer ${owner_first_name} ${owner_last_name} has added you as an employee.\nHead to the following link and use this username to login: ${employee_username}\n${linkToInclude}`;
};
