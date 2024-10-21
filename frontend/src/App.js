import React, { useEffect, useState } from 'react'; // Import necessary hooks
import { Container, Typography, Button } from '@mui/material';  // Import Material UI components
import './App.css';

function App() {

    const [message, setMessage] = useState('');
    const [count, setCount] = useState(0)

    useEffect(() => {
        // Fetching data from the Express backend
        fetch('http://localhost:5000/api/data')  // Replace with your backend URL
            .then(response => response.json())   // Parse the JSON response
            .then(data => setMessage(data.message))  // Set the message from the response
            .catch(error => console.error('Error fetching data:', error));  // Handle any errors

        fetch('http://localhost:5000/api/count')
            .then(response => response.json())
            .then(data => setCount(data.count))
            .catch(error => console.error('Error fetching count:', error));

    }, []);  // Empty dependency array ensures this runs only once when the component mounts

    const incrementCount = () => {
        fetch('http://localhost:5000/api/increment', {method:"POST"})
            .then(response => response.json())
            .then(data => setCount(data.count))
            .catch(error => console.error('Error fetching count:', error));
    }; 


    return (
        <Container>
            <div className="App">
            <Typography variant='h2'>Welcome to our 312 App</Typography>
            <br></br>
            <Typography variant='h6'> Data from Backend: {message} </Typography>
            <Button variant='Contained' color='primary' onClick={incrementCount}>
                Touch Me
            </Button>
            <Typography>
                {count}
            </Typography>
        </div>
        </Container>
    );
}

export default App;
