import express from "express";
const app = express();
const port = 8000;
app.use(express.json());
app.get('/', (req, res) => {
    res.send("Hello world");
});
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
//# sourceMappingURL=index.js.map