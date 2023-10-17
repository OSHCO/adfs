<?php
namespace oshco\adfs;

/**
 * An interface which is used to represent ADFS user.
 */
interface ADFSUser {
    /**
     * Returns the unique identifier of the user.
     */
    public function getId();
}
