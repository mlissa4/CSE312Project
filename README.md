# Project Part 2 Explanation
### Website link : https://8san.xyz/ 
- Users need to be logged in to use features (posting/DM).
- Posting does not use WebSockets, so users will need to refresh their page to view new posts or review changes from other users.
- The DM user list will also require a page refresh when a new user logs in to see the option in the DM list.
- **WebSockets are used for direct messaging: after clicking to send a DM, the messaging page updates in realtime.**
  

  
# Project 3 Part 3 Explanation
- Our feature for part 3 is a profile a section and post managmement for oue site. When users first register they are now given a default profile - - picture.
- This profile picture is visable under thier name on all of thier posts.
- Once logged in users can navigate to their profile page to upload a new profile picture, delete any of thier own posts, and view the stats on all of thier current posts.


# To test this procedure
1. Start your server using docker compose up
2. Register and Login to the site using the register button on the top right
3. make a post using the post button and verify that a default grey profile picture is visable under your post
4. navigate to the profile page and upload an image as a jpg, gif or png
5. verify your profile image has been updated
6. go to your profile page and make note of your current stats
7. on a second browser register a new account and leave a 1 star review on your post
8. on your first browser refresh the porfile page and verify your stats have changed
9. on your first browser delete your post, verify post has been deleted and your stats have changed