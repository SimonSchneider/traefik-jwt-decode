FROM scratch
COPY --chown=0:0 bin/main /
USER 65534

VOLUME ["/config"]

ENV CLAIM_MAPPING_FILE="/config/config.json"
EXPOSE 8080

ENTRYPOINT ["/main"]
