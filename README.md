### Website link : https://8san.xyz/ 
  
# Project 3 Part 3 Explanation
- Our feature for part 3 is a profile a section and post managmement for oue site. When users first register they are now given a default profile - - picture.
- This does not overlap with project part 2 multimedia as that is covered by our posting feature
- This profile picture is visable under their name on all of thier posts.
- Once logged in users can navigate to their profile page to upload a new profile picture, delete any of thier own posts, and view the stats on all of thier current posts.


# To test this procedure 
1. Start your server using docker compose up
2. Register and Login to the site using the register button on the top right
3. make a post using the post button and verify that a default grey profile picture is visable under your post (may need to refresh page to see post)
4. navigate to the profile page and upload an image as a jpg, gif or png
5. verify your profile image has been updated (refresh page if necessary)
6. go to your profile page and make note of your current stats (stat does not need to be completely accurate)
7. on a second browser register a new account and leave a 1 star review on your post and verify that you could see the profile picture of the uploader
8. on your first browser refresh the porfile page and verify your stats have changed (stats does not need to be completely accurate)
9. on your first browser delete your post, click on our picture(top left corner) and refresh both pages on both browsers, verify post has been deleted and your stats have changed (again stats does not need to be completely accurate)
