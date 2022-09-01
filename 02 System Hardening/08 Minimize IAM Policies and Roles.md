# Minimize IAM Policies and Roles

It is not expected to have a question about iAM for the exam but it is good to understand them at a high level

- In AWS the first account that is created when you sign up is the root account.  
- This account should not be used in day to day operations.  
- Root should only be used to create other users.  
- New user accounts are assigned the least privilege  
- We can assign IAM policies to users
- We can create an IAM group and assign users to that group and give that group capabilities.
- Services do not automatically have the ability to talk to other services
- We have to create a role to allow a service to talk to another service
- There are other ways of granting access but they are less secure, always use IAM Policies
- Occasionally audit IAM policies to ensure they have the least number of privileges.  AWS Trusted Advisor can help with this.
