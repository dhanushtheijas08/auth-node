import { Verification_Type as verificationType } from "@prisma/client";

export const emailTemplate = (
  type: verificationType,
  validationCode: string
) => {
  switch (type) {
    case "VERIFY_EMAIL":
      return verificationEmail(validationCode);

    default:
      break;
  }
};

const verificationEmail = (validationCode: string) => {
  return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html dir="ltr" lang="en">
  <head>
    <link
      rel="preload"
      as="image"
      href="https://react-email-demo-mbr0z06jp-resend.vercel.app/static/slack-logo.png" />
    <link
      rel="preload"
      as="image"
      href="https://react-email-demo-mbr0z06jp-resend.vercel.app/static/slack-twitter.png" />
    <link
      rel="preload"
      as="image"
      href="https://react-email-demo-mbr0z06jp-resend.vercel.app/static/slack-facebook.png" />
    <link
      rel="preload"
      as="image"
      href="https://react-email-demo-mbr0z06jp-resend.vercel.app/static/slack-linkedin.png" />
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type" />
    <meta name="x-apple-disable-message-reformatting" />
    <!--$-->
  </head>
  <body style="background-color:#ffffff">
    <table
      border="0"
      width="100%"
      cellpadding="0"
      cellspacing="0"
      role="presentation"
      align="center">
      <tbody>
        <tr>
          <td
            style="background-color:#ffffff;margin:0 auto;font-family:-apple-system, BlinkMacSystemFont, &#x27;Segoe UI&#x27;, &#x27;Roboto&#x27;, &#x27;Oxygen&#x27;, &#x27;Ubuntu&#x27;, &#x27;Cantarell&#x27;, &#x27;Fira Sans&#x27;, &#x27;Droid Sans&#x27;, &#x27;Helvetica Neue&#x27;, sans-serif">
            <div
              style="display:none;overflow:hidden;line-height:1px;opacity:0;max-height:0;max-width:0"
              data-skip-in-text="true">
              Confirm your email address
              <div>
                 ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿ ‌​‍‎‏﻿
              </div>
            </div>
            <table
              align="center"
              width="100%"
              border="0"
              cellpadding="0"
              cellspacing="0"
              role="presentation"
              style="max-width:37.5em;margin:0 auto;padding:0px 20px">
              <tbody>
                <tr style="width:100%">
                  <td>
                    <table
                      align="center"
                      width="100%"
                      border="0"
                      cellpadding="0"
                      cellspacing="0"
                      role="presentation"
                      style="margin-top:32px">
                      <tbody>
                        <tr>
                          <td>
                            <img
                              alt="Slack"
                              height="36"
                              src="https://react-email-demo-mbr0z06jp-resend.vercel.app/static/slack-logo.png"
                              style="display:block;outline:none;border:none;text-decoration:none"
                              width="120" />
                          </td>
                        </tr>
                      </tbody>
                    </table>
                    <h1
                      style="color:#1d1c1d;font-size:36px;font-weight:700;margin:30px 0;padding:0;line-height:42px">
                      Confirm your email address
                    </h1>
                    <p
                      style="font-size:20px;line-height:28px;margin-bottom:30px;margin-top:16px">
                      Your confirmation code is below - enter it in your open
                      browser window and we&#x27;ll help you get signed in.
                    </p>
                    <table
                      align="center"
                      width="100%"
                      border="0"
                      cellpadding="0"
                      cellspacing="0"
                      role="presentation"
                      style="background:rgb(245, 244, 245);border-radius:4px;margin-bottom:30px;padding:40px 10px">
                      <tbody>
                        <tr>
                          <td>
                            <p
                              style="font-size:30px;line-height:24px;text-align:center;vertical-align:middle;margin-top:16px;margin-bottom:16px">
                              ${validationCode}
                            </p>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                    <p
                      style="font-size:14px;line-height:24px;color:#000;margin-top:16px;margin-bottom:16px">
                      If you didn&#x27;t request this email, there&#x27;s
                      nothing to worry about, you can safely ignore it.
                    </p>
                    <table
                      align="center"
                      width="100%"
                      border="0"
                      cellpadding="0"
                      cellspacing="0"
                      role="presentation">
                      <tbody>
                        <tr>
                          <td>
                            <table
                              align="center"
                              width="100%"
                              border="0"
                              cellpadding="0"
                              cellspacing="0"
                              role="presentation"
                              style="margin-bottom:32px;padding-left:8px;padding-right:8px">
                              <tbody style="width:100%">
                                <tr style="width:100%">
                                  <td
                                    data-id="__react-email-column"
                                    style="width:66%">
                                    <img
                                      alt="Slack"
                                      height="36"
                                      src="https://react-email-demo-mbr0z06jp-resend.vercel.app/static/slack-logo.png"
                                      style="display:block;outline:none;border:none;text-decoration:none"
                                      width="120" />
                                  </td>
                                  <td
                                    align="right"
                                    data-id="__react-email-column">
                                    <a
                                      href="/"
                                      style="color:#067df7;text-decoration-line:none"
                                      target="_blank"
                                      ><img
                                        alt="Slack"
                                        height="32"
                                        src="https://react-email-demo-mbr0z06jp-resend.vercel.app/static/slack-twitter.png"
                                        style="display:inline;outline:none;border:none;text-decoration:none;margin-left:8px"
                                        width="32" /></a
                                    ><a
                                      href="/"
                                      style="color:#067df7;text-decoration-line:none"
                                      target="_blank"
                                      ><img
                                        alt="Slack"
                                        height="32"
                                        src="https://react-email-demo-mbr0z06jp-resend.vercel.app/static/slack-facebook.png"
                                        style="display:inline;outline:none;border:none;text-decoration:none;margin-left:8px"
                                        width="32" /></a
                                    ><a
                                      href="/"
                                      style="color:#067df7;text-decoration-line:none"
                                      target="_blank"
                                      ><img
                                        alt="Slack"
                                        height="32"
                                        src="https://react-email-demo-mbr0z06jp-resend.vercel.app/static/slack-linkedin.png"
                                        style="display:inline;outline:none;border:none;text-decoration:none;margin-left:8px"
                                        width="32"
                                    /></a>
                                  </td>
                                </tr>
                              </tbody>
                            </table>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                    <table
                      align="center"
                      width="100%"
                      border="0"
                      cellpadding="0"
                      cellspacing="0"
                      role="presentation">
                      <tbody>
                        <tr>
                          <td>
                            <a
                              href="https://slackhq.com"
                              rel="noopener noreferrer"
                              style="color:#b7b7b7;text-decoration-line:none;text-decoration:underline"
                              target="_blank"
                              >Our blog</a
                            >   |   <a
                              href="https://slack.com/legal"
                              rel="noopener noreferrer"
                              style="color:#b7b7b7;text-decoration-line:none;text-decoration:underline"
                              target="_blank"
                              >Policies</a
                            >   |   <a
                              href="https://slack.com/help"
                              rel="noopener noreferrer"
                              style="color:#b7b7b7;text-decoration-line:none;text-decoration:underline"
                              target="_blank"
                              >Help center</a
                            >   |   <a
                              href="https://slack.com/community"
                              rel="noopener noreferrer"
                              data-auth="NotApplicable"
                              data-linkindex="6"
                              style="color:#b7b7b7;text-decoration-line:none;text-decoration:underline"
                              target="_blank"
                              >Slack Community</a
                            >
                            <p
                              style="font-size:12px;line-height:15px;color:#b7b7b7;text-align:left;margin-bottom:50px;margin-top:16px">
                              ©2022 Slack Technologies, LLC, a Salesforce
                              company. <br />500 Howard Street, San Francisco,
                              CA 94105, USA <br /><br />All rights reserved.
                            </p>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </td>
                </tr>
              </tbody>
            </table>
          </td>
        </tr>
      </tbody>
    </table>
    <!--/$-->
  </body>
</html>
`;
};
