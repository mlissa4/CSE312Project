function logoutFeature() {
    const response = fetch("/logout", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({})

    }) .then(response => {
        if(response.ok){
            window.location.href="/";
        }
    })

}