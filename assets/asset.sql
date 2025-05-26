CREATE TABLE assets (
    id VARCHAR PRIMARY KEY, -- Unique identifier for the asset
    Asset_Name VARCHAR NOT NULL, -- The human-readable name of the asset (e.g., server name, website name)
    Asset_IP VARCHAR, -- The IP address of the asset, if applicable (e.g., for hosts)
    Asset_OS VARCHAR, -- Operating system of the asset (e.g., Windows, Linux)
    OS_Version VARCHAR, -- Version of the operating system running on the asset
    Asset_Last_Seen TIMESTAMP, -- The last date and time the asset was seen or scanned
    Asset_Tags TEXT, -- JSON array of tags or labels associated with the asset for categorisation and filtering
    Business_Groups TEXT, -- JSON array of business groups or organisational units responsible for or associated with this asset
    Owners TEXT, -- JSON array of dynamic properties indicating the owners or responsible parties for this asset
    Inclusion_Date TIMESTAMP, -- The date when this asset was included or imported into the asset management system
    Cloud_Instance_ID VARCHAR, -- Cloud instance identifier if this is a cloud-based asset
    Asset_State VARCHAR, -- Current state of the asset (e.g., Running, Stopped)
    Asset_First_Seen TIMESTAMP, -- The first date and time the asset was seen or added to the system
    Type VARCHAR NOT NULL, -- The high-level type of asset (e.g., Host, Website, Code Project, Image, Cloud Resource)
    Provider VARCHAR, -- Cloud provider for cloud resources (e.g., AWS, Azure, GCP)
    Subtype VARCHAR, -- Specific subtype of the asset, as defined in asset_types.yaml (e.g., EC2 Instance, S3 Bucket, Web Application)
    Custom_Field1 VARCHAR, -- Custom field for additional metadata
    Custom_Field2 VARCHAR, -- Custom field for additional metadata
    Custom_Field3 VARCHAR  -- Custom field for additional metadata
); 