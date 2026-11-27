"""Exercise the AWID fixture's removal of the disposable containers it owns."""

import subprocess
import unittest

from awid_fixture import remove_owned_containers, run


def anonymous_volume(container):
    return run(
        "docker", "inspect", container, "--format", "{{range .Mounts}}{{.Name}}{{end}}"
    )


def volume_exists(volume):
    return (
        subprocess.run(
            ["docker", "volume", "inspect", volume],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


class OwnedContainerRemoval(unittest.TestCase):
    def start(self, *options):
        # redis:7 declares a /data volume, so each container gets an anonymous one.
        container = run("docker", "run", "-d", *options, "redis:7")
        volume = anonymous_volume(container)
        self.assertTrue(volume, container)
        self.addCleanup(
            subprocess.run,
            ["docker", "rm", "-f", "-v", container],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(
            subprocess.run,
            ["docker", "volume", "rm", volume],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return container, volume

    def test_owned_container_volumes_are_removed_and_others_kept(self):
        # The fixture starts its containers with --rm; removing one explicitly
        # still has to remove its anonymous volume.
        owned, owned_volume = self.start("--rm")
        bystander, bystander_volume = self.start()

        remove_owned_containers([owned])

        self.assertFalse(volume_exists(owned_volume), owned_volume)
        self.assertEqual(
            run("docker", "inspect", bystander, "--format", "{{.State.Running}}"),
            "true",
        )
        self.assertTrue(volume_exists(bystander_volume), bystander_volume)


if __name__ == "__main__":
    unittest.main()
