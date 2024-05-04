const express = require('express');
const nodemailer = require('nodemailer');

const app = express();
const port = 3000;

// Set up Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail', // For example, Gmail. You can use other services as well.
  auth: {
    user: 'netmansautomail@gmail.com',
    pass: 'hogmjgkmqodaozlp'
  }
});

// Define a route that triggers an email
app.get('/send-mail', (req, res) => {
  const mailOptions = {
    from: 'netmansautomail@gmail.com',
    to: 'naveendhananjaya2001@gmail.com',
    subject: 'New Login Detected',
    text: 'A new login to your account was detected.'
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      res.send('Error sending email');
    } else {
      console.log('Email sent: ' + info.response);
      res.send('Email sent successfully');
    }
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
