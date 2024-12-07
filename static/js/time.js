document.addEventListener("DOMContentLoaded", () => {
    const posts = document.querySelectorAll('.gallery .image_box');
    posts.forEach(post => {
        const Element = post.querySelector('.Expiration');
        const countdownElement = post.querySelector('.Countdown');  
        const Expiration = new Date(Element.textContent.replace('Expires at: ', '').trim());
        Expiration.setHours(Expiration.getHours() - 5);
        if (isNaN(Expiration.getTime())) {
            return;
        }
        // Countdown
        function Countdown() {
            const now = new Date();
            const timeDiff = Expiration - now;

            if (timeDiff > 0) {
                const hours = Math.floor(timeDiff / (1000 * 60 * 60));
                const minutes = Math.floor((timeDiff % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((timeDiff % (1000 * 60)) / 1000);
                countdownElement.textContent  = `Expires in: ${hours}h ${minutes}m ${seconds}s`;
            } else {
                countdownElement.textContent  = "Expired";
            }
        }
        // Repeat countdown
        Countdown();
        setInterval(Countdown, 1000);
    });
});
