# MeeSignHelper

A helper tool to provide PDF-handling capabilities to [MeeSign server](https://github.com/crocs-muni/meesign-server) application.

## Usage

```
# Build the tool
mvn clean compile assembly:single

# Copy the built jar to your MeeSign directory
cp target/signPDF-1.0-SNAPSHOT-jar-with-dependencies.jar $MEESIGN/MeeSignHelper.jar
```
