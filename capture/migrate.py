import yaml


for name in ["chrome", "edge", "firefox", "safari"]:
    with open(f"old_signatures/{name}.yaml") as f:
        for config in yaml.safe_load_all(f.read()):
            http2 = config["signature"]["http2"]
            http2_frames = {"frames": [{"frame_type": "HEADERS", **http2}]}
            config["signature"]["http2"] = http2_frames
            with open(f"signatures/{config['name']}.yaml", "w") as wf:
                wf.write(yaml.safe_dump(config))
