import { useContext, useState } from "react";
import { Button, Container, TextField, FormGroup } from "@mui/material";
import { UserContext } from "../context/User";

export const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const { login } = useContext(UserContext);

  return (
    <Container>
      <FormGroup className="mb-3" controlId="formBasicEmail">
        <TextField
          type="email"
          placeholder="Enter email"
          value={email}
          label="Email address"
          onChange={(e) => setEmail(e.target.value)}
        />
      </FormGroup>
      <FormGroup className="mb-3" controlId="formBasicPassword">
        <TextField
          type="password"
          placeholder="Password"
          label="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </FormGroup>
      <Button variant="primary" onClick={() => login(email, password)}>
        Submit
      </Button>
    </Container>
  );
};
