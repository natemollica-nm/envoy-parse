import React, { useState } from "react";
import axios from "axios";
import { Card, CardHeader, CardContent, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";

export default function EnvoyUI() {
    const [apiUrl, setApiUrl] = useState("http://localhost:19000");
    const [file, setFile] = useState(null);
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [open, setOpen] = useState(false);

    const handleFileUpload = (event) => {
        setFile(event.target.files[0]);
        setError(null);
    };

    const fetchDataFromApi = async () => {
        try {
            const response = await axios.get(`${apiUrl}/config_dump?include_eds`);
            setData(response.data);
            setError(null);
            setOpen(true);
        } catch (err) {
            setError("Failed to fetch data from the API. Check the URL.");
        }
    };

    const handleFileSubmit = async () => {
        if (!file) {
            setError("Please upload a file first.");
            return;
        }
        const reader = new FileReader();
        reader.onload = (event) => {
            try {
                const jsonData = JSON.parse(event.target.result);
                setData(jsonData);
                setError(null);
                setOpen(true);
            } catch (err) {
                setError("Failed to parse the uploaded file. Make sure it's valid JSON.");
            }
        };
        reader.readAsText(file);
    };

    const visualizeRelationships = () => {
        if (!data) {
            setError("No data available to visualize.");
            return null;
        }

        const relationships = buildRelationships(data); // Assuming the build_relationships function exists in your backend
        return (
            <div className="grid grid-cols-1 gap-4">
                {relationships.map((item, index) => (
                    <Card key={index}>
                        <CardHeader>
                            <CardTitle>Listener: {item.listener}</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <p>Filter Chain: {item.filterChain}</p>
                            <p>Cluster: {item.cluster}</p>
                            <p>Endpoints: {item.endpoints.join(", ")}</p>
                        </CardContent>
                    </Card>
                ))}
            </div>
        );
    };

    return (
        <div className="p-4">
            <h1 className="text-xl font-bold mb-4">Envoy Proxy Tool</h1>

            <div className="mb-4">
                <h2 className="font-semibold">Fetch Data from Envoy Admin API</h2>
                <Input
                    type="text"
                    value={apiUrl}
                    onChange={(e) => setApiUrl(e.target.value)}
                    placeholder="Enter Envoy Admin API URL"
                    className="mb-2"
                />
                <Button onClick={fetchDataFromApi}>Fetch Data</Button>
            </div>

            <div className="mb-4">
                <h2 className="font-semibold">Upload Config File</h2>
                <Input type="file" accept=".json" onChange={handleFileUpload} className="mb-2" />
                <Button onClick={handleFileSubmit}>Submit File</Button>
            </div>

            {error && <div className="text-red-500 mb-4">{error}</div>}

            <Dialog open={open} onOpenChange={setOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Visualization</DialogTitle>
                    </DialogHeader>
                    {visualizeRelationships()}
                </DialogContent>
            </Dialog>
        </div>
    );
}

// Mock implementation for buildRelationships (replace with real logic)
function buildRelationships(data) {
    // Example structure to mimic relationships
    return [
        {
            listener: "Listener 0",
            filterChain: "filter_chain_1",
            cluster: "Cluster 0",
            endpoints: ["Endpoint 0", "Endpoint 1"],
        },
    ];
}
