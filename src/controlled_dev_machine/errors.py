class ControlledDevMachineError(Exception):
    """Base error shown to the operator without a traceback."""


class ConfigError(ControlledDevMachineError):
    """Host configuration is invalid."""


class PolicyError(ControlledDevMachineError):
    """Policy snapshot is invalid."""


class ReviewError(ControlledDevMachineError):
    """Request review state is invalid or changed concurrently."""


class DeploymentError(ControlledDevMachineError):
    """Generated runtime state is unsafe, incomplete, or failed to deploy."""


class SessionMigrationError(ControlledDevMachineError):
    """A Claude session cannot be imported without losing its safety guarantees."""
